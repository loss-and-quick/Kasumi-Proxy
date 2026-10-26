//! Synthetic real-Xray traffic and emitted-config regressions for provider routing.
//!
//! Regressions test that:
//! 1. Provider Xray graph import correctly identifies the default routing target (e.g.
//!    a balancer rather than blindly selecting the first outbound when a decoy/broken
//!    outbound is placed first).
//! 2. Balancer selectors and observatory subjectSelectors do not capture client-owned
//!    outbounds (`direct`, `block`, `dns-out`, `force-in`, etc.).
//! 3. Internal loopback transitions (`inboundTag` virtual rules) precede user rules so
//!    cascades are not intercepted by user direct/block/profile matching.
//! 4. Virtual tags avoid collision with Kasumi's internal routing mechanisms.
//! 5. Real traffic sent through Kasumi's `force-in` port reaches the healthy member
//!    selected by the balancer (bypassing the first decoy), and correctly cascades to
//!    fallback members via loopback virtual transitions when the preferred member is down.
//!
//! Real-core tests run only when an Xray binary is present (via `KASUMI_XRAY_BIN` or
//! `src-tauri/binaries/xray*`). When absent, real-core execution skips cleanly with a note,
//! while static emitted-config assertions always run. All traffic is self-contained to
//! localhost (127.0.0.1) with zero external DNS or network access.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use kasumi_core::custom_target::Target;
use kasumi_core::profile::{CustomOrigin, Profile};
use kasumi_core::state::{AdvancedSettings, RoutingMode, RoutingRule, force_socks_port};
use kasumi_core::xray_config::{build_xray_config, build_xray_probe_config};

const PROBE_URL: &str = "http://probe.example/health";

fn binaries_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../src-tauri/binaries")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../src-tauri/binaries"))
}

fn find_xray_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("KASUMI_XRAY_BIN") {
        let path = PathBuf::from(&p);
        if !path.is_file() {
            panic!("KASUMI_XRAY_BIN is set to '{p}', but binary does not exist or is not a file");
        }
        return Some(path);
    }
    let dir = binaries_dir();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("xray") && !name_str.ends_with(".dll") {
                return Some(e.path());
            }
        }
    }
    None
}

/// RAII guard ensuring the Xray child process is killed and reaped on test exit or panic.
struct ChildGuard(Option<Child>);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Read the tail of a log file up to `max_lines` for bounded error reporting.
fn read_log_tail(log_path: &Path, max_lines: usize) -> String {
    if let Ok(content) = std::fs::read_to_string(log_path) {
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(max_lines);
        lines[start..].join("\n")
    } else {
        "<unable to read log file>".to_string()
    }
}

/// Wait for traffic routed through `force_port` to match `expected_marker`.
///
/// Bounded retry loop (up to `timeout`, e.g. 15s) that does not rely on fixed sleep
/// assumptions. Treats mismatched responses as interim/diagnostic rather than success.
/// Inspects child process status on every iteration and includes bounded log tail on error.
fn wait_for_traffic_marker(
    guard: &mut ChildGuard,
    force_port: u16,
    expected_marker: &str,
    log_path: &Path,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut last_response = None;
    let mut last_error = None;

    while Instant::now() < deadline {
        if let Ok(Some(status)) = guard.0.as_mut().unwrap().try_wait() {
            let tail = read_log_tail(log_path, 40);
            panic!("xray exited prematurely during traffic test with status {status}:\n{tail}");
        }

        match send_socks5_http_request(force_port, "probe.example", 80, "/app-traffic") {
            Ok(resp) => {
                if resp.contains(expected_marker) {
                    return resp;
                }
                last_response = Some(resp);
            }
            Err(err) => {
                last_error = Some(err);
            }
        }
        thread::sleep(Duration::from_millis(150));
    }

    let tail = read_log_tail(log_path, 40);
    panic!(
        "Traffic test failed to route to expected marker '{expected_marker}' within {:?}.\n\
         Last response: {:?}\n\
         Last error: {:?}\n\
         Xray stderr tail:\n{}",
        timeout, last_response, last_error, tail
    );
}

/// Allocate 3 consecutive/available loopback ports for Kasumi inbounds:
/// `(local_socks_port, local_http_port, force_port)`.
fn allocate_kasumi_inbound_ports() -> (u16, u16, u16) {
    for _ in 0..100 {
        if let Ok(l1) = TcpListener::bind("127.0.0.1:0") {
            let base = l1.local_addr().unwrap().port();
            drop(l1);
            let socks = base;
            let http = base.saturating_add(1);
            let force = force_socks_port(socks, http);

            if let Ok(t1) = TcpListener::bind(format!("127.0.0.1:{socks}"))
                && let Ok(t2) = TcpListener::bind(format!("127.0.0.1:{http}"))
                && let Ok(t3) = TcpListener::bind(format!("127.0.0.1:{force}"))
            {
                drop(t1);
                drop(t2);
                drop(t3);
                return (socks, http, force);
            }
        }
    }
    panic!("failed to allocate free ports for kasumi inbounds");
}

/// Minimal deterministic SOCKS5 relay implemented in std::net.
///
/// Operates entirely on loopback. Responds to:
/// - SOCKS5 greeting + connect requests.
/// - Upstream HTTP health checks (`HEAD` or `/health`): responds `HTTP/1.1 204 No Content`.
/// - Application HTTP requests (`GET`): responds `HTTP/1.1 200 OK` with a body marker
///   identifying the node (`node_id`).
/// - Unhealthy state: rejects SOCKS5 authentication / connection to simulate node failure.
pub struct MockRelay {
    pub port: u16,
    pub is_healthy: Arc<AtomicBool>,
    pub requests_served: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockRelay {
    pub fn start(node_id: &'static str, initial_healthy: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock relay listener");
        let port = listener.local_addr().expect("local addr").port();
        listener
            .set_nonblocking(true)
            .expect("set nonblocking on relay");

        let is_healthy = Arc::new(AtomicBool::new(initial_healthy));
        let requests_served = Arc::new(AtomicUsize::new(0));
        let shutdown = Arc::new(AtomicBool::new(false));

        let is_healthy_clone = Arc::clone(&is_healthy);
        let requests_clone = Arc::clone(&requests_served);
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let healthy = is_healthy_clone.load(Ordering::SeqCst);
                        let req_counter = Arc::clone(&requests_clone);
                        thread::spawn(move || {
                            handle_mock_connection(stream, healthy, node_id, req_counter);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            is_healthy,
            requests_served,
            shutdown,
            handle: Some(handle),
        }
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::SeqCst);
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for MockRelay {
    fn drop(&mut self) {
        self.stop();
    }
}

fn handle_mock_connection(
    mut stream: TcpStream,
    healthy: bool,
    node_id: &'static str,
    req_counter: Arc<AtomicUsize>,
) {
    let timeout = Some(Duration::from_secs(3));
    let _ = stream.set_read_timeout(timeout);
    let _ = stream.set_write_timeout(timeout);

    // 1. SOCKS5 Greeting: [VER, NMETHODS, METHODS...]
    let mut header = [0u8; 2];
    if stream.read_exact(&mut header).is_err() || header[0] != 0x05 {
        return;
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    if stream.read_exact(&mut methods).is_err() {
        return;
    }

    if !healthy {
        let _ = stream.write_all(&[0x05, 0xff]); // No acceptable methods
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    // Accept NO AUTH
    if stream.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    let _ = stream.flush();

    // 2. SOCKS5 Request: [VER, CMD, RSV, ATYP, ADDR..., PORT]
    let mut req_header = [0u8; 4];
    if stream.read_exact(&mut req_header).is_err() || req_header[0] != 0x05 || req_header[1] != 0x01
    {
        return;
    }
    match req_header[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            if stream.read_exact(&mut ip).is_err() {
                return;
            }
        }
        0x03 => {
            let mut len = [0u8; 1];
            if stream.read_exact(&mut len).is_err() {
                return;
            }
            let mut domain = vec![0u8; len[0] as usize];
            if stream.read_exact(&mut domain).is_err() {
                return;
            }
        }
        0x04 => {
            let mut ip = [0u8; 16];
            if stream.read_exact(&mut ip).is_err() {
                return;
            }
        }
        _ => return,
    }
    let mut port_bytes = [0u8; 2];
    if stream.read_exact(&mut port_bytes).is_err() {
        return;
    }

    // Success response: 127.0.0.1:80
    let reply = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
    if stream.write_all(&reply).is_err() {
        return;
    }
    let _ = stream.flush();

    // 3. HTTP Request
    let mut buf = [0u8; 1024];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let req_str = String::from_utf8_lossy(&buf[..n]);

    req_counter.fetch_add(1, Ordering::SeqCst);

    if req_str.starts_with("HEAD") || req_str.contains("/health") {
        // Xray healthping expects 204 No Content for successful health probes
        let resp = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes());
    } else {
        // Application payload request
        let body = format!("OK node={node_id}");
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
    drop(stream);
}

/// Send an HTTP request through Kasumi's generated SOCKS5 `force-in` port.
fn send_socks5_http_request(
    force_port: u16,
    target_host: &str,
    target_port: u16,
    path: &str,
) -> Result<String, String> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{force_port}"))
        .map_err(|e| format!("connect to force-in port {force_port} failed: {e}"))?;

    let timeout = Some(Duration::from_secs(3));
    stream
        .set_read_timeout(timeout)
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(timeout)
        .map_err(|e| e.to_string())?;

    // SOCKS5 Greeting
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .map_err(|e| format!("write greeting failed: {e}"))?;
    let mut greeting_resp = [0u8; 2];
    stream
        .read_exact(&mut greeting_resp)
        .map_err(|e| format!("read greeting failed: {e}"))?;
    if greeting_resp != [0x05, 0x00] {
        return Err(format!("socks5 greeting rejected: {:?}", greeting_resp));
    }

    // SOCKS5 CONNECT
    let host_bytes = target_host.as_bytes();
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    connect_req.extend_from_slice(host_bytes);
    connect_req.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&connect_req)
        .map_err(|e| format!("write connect req failed: {e}"))?;

    let mut connect_resp = [0u8; 4];
    stream
        .read_exact(&mut connect_resp)
        .map_err(|e| format!("read connect resp failed: {e}"))?;
    if connect_resp[0] != 0x05 || connect_resp[1] != 0x00 {
        return Err(format!(
            "socks5 connect failed with status: 0x{:02x}",
            connect_resp[1]
        ));
    }
    match connect_resp[3] {
        0x01 => {
            let mut rem = [0u8; 6];
            stream
                .read_exact(&mut rem)
                .map_err(|e| format!("read connect rem ipv4 failed: {e}"))?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|e| format!("read connect len failed: {e}"))?;
            let mut rem = vec![0u8; len[0] as usize + 2];
            stream
                .read_exact(&mut rem)
                .map_err(|e| format!("read connect rem domain failed: {e}"))?;
        }
        0x04 => {
            let mut rem = [0u8; 18];
            stream
                .read_exact(&mut rem)
                .map_err(|e| format!("read connect rem ipv6 failed: {e}"))?;
        }
        _ => return Err("invalid atyp in socks5 connect response".to_string()),
    }

    // HTTP GET
    let http_req =
        format!("GET {path} HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(http_req.as_bytes())
        .map_err(|e| format!("write http req failed: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("flush http req failed: {e}"))?;

    let mut resp = String::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                resp.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if resp.contains("\r\n\r\n") && resp.contains("OK node=") {
                    break;
                }
            }
            Err(e) => return Err(format!("read error: {e}")),
        }
    }
    Ok(resp)
}

/// Build a synthetic Custom profile with:
/// - 1st outbound: deliberately broken decoy (verifies Kasumi does NOT blindly pick the first outbound)
/// - 2nd outbound: primary relay SOCKS outbound
/// - 3rd outbound: fallback relay SOCKS outbound
/// - 4th outbound: loopback outbound with `settings.inboundTag = "virtual-fallback-in"`
/// - Balancer with `leastLoad`, `selector = ["node-primary"]`, `fallbackTag = "loopback-fb"`
/// - Virtual loopback fallback rule: `inboundTag = ["virtual-fallback-in"]` -> `node-fallback`
/// - Default routing rule targeting `balancer-primary`
/// - `burstObservatory` targeting `node-primary` and `node-fallback` with probe URL `http://probe.example/health`
fn build_synthetic_custom_profile(
    decoy_port: u16,
    primary_port: u16,
    fallback_port: u16,
    origin: CustomOrigin,
) -> Profile {
    let raw = json!({
        "outbounds": [
            {
                "tag": "decoy-dead",
                "protocol": "socks",
                "settings": {
                    "servers": [{ "address": "127.0.0.1", "port": decoy_port }]
                }
            },
            {
                "tag": "node-primary",
                "protocol": "socks",
                "settings": {
                    "servers": [{ "address": "127.0.0.1", "port": primary_port }]
                }
            },
            {
                "tag": "node-fallback",
                "protocol": "socks",
                "settings": {
                    "servers": [{ "address": "127.0.0.1", "port": fallback_port }]
                }
            },
            {
                "tag": "loopback-fb",
                "protocol": "loopback",
                "settings": {
                    "inboundTag": "virtual-fallback-in"
                }
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [
                {
                    "tag": "balancer-primary",
                    "selector": ["node-primary"],
                    "strategy": { "type": "leastLoad" },
                    "fallbackTag": "loopback-fb"
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["virtual-fallback-in"],
                    "outboundTag": "node-fallback",
                    "network": "tcp,udp"
                },
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "balancer-primary"
                }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "destination": PROBE_URL,
                "interval": "10s",
                "timeout": "2s",
                "sampling": 1
            },
            "subjectSelector": ["node-primary", "node-fallback"]
        }
    });

    serde_json::from_value(json!({
        "protocol": "custom",
        "meta": {
            "id": "synthetic-provider",
            "remarks": "Synthetic Provider",
            "groupId": "g-test"
        },
        "raw": raw.to_string(),
        "origin": origin,
    }))
    .expect("deserialize synthetic custom profile")
}

fn build_synthetic_provider_profile(
    decoy_port: u16,
    primary_port: u16,
    fallback_port: u16,
) -> Profile {
    build_synthetic_custom_profile(
        decoy_port,
        primary_port,
        fallback_port,
        CustomOrigin::Provider,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Pure Emitted-Config Assertions (Static assertions, run in all environments)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_emitted_config_default_target_is_not_first_decoy() {
    let profile = build_synthetic_provider_profile(1, 10801, 10802);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[])
        .expect("build probe config for synthetic provider");

    // The default target must be a Balancer, never the first decoy outbound
    match probe.target {
        Target::Balancer { .. } => {}
        Target::Outbound(ref tag) => {
            panic!("probe target was incorrectly chosen as Outbound({tag}), not Balancer");
        }
    }
}

#[test]
fn test_emitted_config_selector_prefix_isolation() {
    let profile = build_synthetic_provider_profile(1, 10801, 10802);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[])
        .expect("build probe config for synthetic provider");

    let cfg = &probe.config;
    let balancers = cfg["routing"]["balancers"].as_array();
    if let Some(balancers) = balancers {
        for b in balancers {
            if let Some(selectors) = b["selector"].as_array() {
                for sel in selectors.iter().filter_map(Value::as_str) {
                    assert!(
                        !sel.starts_with("direct")
                            && !sel.starts_with("block")
                            && !sel.starts_with("dns-out")
                            && !sel.starts_with("force-in")
                            && !sel.starts_with("socks-in")
                            && !sel.starts_with("http-in"),
                        "balancer selector '{sel}' captures a Kasumi-owned outbound"
                    );
                }
            }
        }
    }

    if let Some(burst) = cfg.get("burstObservatory")
        && let Some(selectors) = burst["subjectSelector"].as_array()
    {
        for sel in selectors.iter().filter_map(Value::as_str) {
            assert!(
                !sel.starts_with("direct")
                    && !sel.starts_with("block")
                    && !sel.starts_with("dns-out")
                    && !sel.starts_with("force-in")
                    && !sel.starts_with("socks-in")
                    && !sel.starts_with("http-in"),
                "burstObservatory selector '{sel}' captures a Kasumi-owned outbound"
            );
        }
    }
}

#[test]
fn test_emitted_config_virtual_tag_collision_and_scoping() {
    // Config with internal loopback tags
    let raw = json!({
        "outbounds": [
            { "tag": "proxy-select", "protocol": "socks", "settings": { "servers": [{ "address": "127.0.0.1", "port": 10801 }] } },
            { "tag": "srv-1", "protocol": "socks", "settings": { "servers": [{ "address": "127.0.0.1", "port": 10802 }] } },
            { "tag": "loop-inbound", "protocol": "loopback", "settings": { "inboundTag": "v-in" } }
        ],
        "routing": {
            "balancers": [
                { "tag": "bal-1", "selector": ["srv-1"], "strategy": { "type": "leastLoad" }, "fallbackTag": "loop-inbound" }
            ],
            "rules": [
                { "type": "field", "inboundTag": ["v-in"], "outboundTag": "srv-1", "network": "tcp,udp" },
                { "type": "field", "network": "tcp,udp", "balancerTag": "bal-1" }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "destination": PROBE_URL,
                "interval": "10s",
                "timeout": "2s",
                "sampling": 1
            },
            "subjectSelector": ["srv-1"]
        }
    });

    let profile: Profile = serde_json::from_value(json!({
        "protocol": "custom",
        "meta": { "id": "test-virtual-collision", "remarks": "Virtual Collision", "groupId": "g-test" },
        "raw": raw.to_string(),
        "origin": "provider",
    }))
    .unwrap();

    let settings = AdvancedSettings {
        routing_mode: RoutingMode::Rules,
        ..AdvancedSettings::default()
    };
    let user_rule = RoutingRule {
        id: "user-rule-1".into(),
        remarks: "User Direct".into(),
        enabled: true,
        outbound_tag: "direct".into(),
        domain: Some(vec!["blocked.example".into()]),
        ip: None,
        port: None,
        network: None,
        protocol: None,
        process: None,
        package_name: None,
        source_ip: None,
    };

    let cfg = build_xray_config(&profile, &settings, &[user_rule], &[])
        .expect("build runtime config with user rules");

    let rules = cfg["routing"]["rules"].as_array().expect("rules array");

    // Internal virtual inbound rules must precede user rules so loopback cascades
    // are not captured by user rules
    let mut virtual_rule_idx = None;
    let mut user_rule_idx = None;
    for (i, r) in rules.iter().enumerate() {
        if let Some(inbound) = r.get("inboundTag").and_then(Value::as_array)
            && inbound.iter().any(|tag| {
                let s = tag.as_str().unwrap_or("");
                s != "socks-in" && s != "http-in" && s != "force-in"
            })
            && virtual_rule_idx.is_none()
        {
            virtual_rule_idx = Some(i);
        }
        if let Some(domains) = r.get("domain").and_then(Value::as_array)
            && domains
                .iter()
                .any(|d| d.as_str().is_some_and(|s| s.contains("blocked.example")))
            && user_rule_idx.is_none()
        {
            user_rule_idx = Some(i);
        }
    }

    if let (Some(v_idx), Some(u_idx)) = (virtual_rule_idx, user_rule_idx) {
        assert!(
            v_idx < u_idx,
            "internal loopback rule (index {v_idx}) must precede user rule (index {u_idx})"
        );
    }
}

#[test]
fn test_emitted_config_burst_observatory_retained() {
    let profile = build_synthetic_provider_profile(1, 10801, 10802);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[])
        .expect("build probe config for synthetic provider");

    let bobs = probe.config.get("burstObservatory");
    assert!(
        bobs.is_some(),
        "probe config must retain burstObservatory for provider graph"
    );
    let bobs = bobs.unwrap();
    assert_eq!(
        bobs["pingConfig"]["destination"], PROBE_URL,
        "burstObservatory pingConfig destination preserved"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Real-Xray Traffic Regressions (Executed only when Xray core is staged)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_real_xray_traffic_healthy_default_selected_over_decoy() {
    let Some(xray_bin) = find_xray_binary() else {
        eprintln!(
            "no staged xray binary found in KASUMI_XRAY_BIN or {}: skipping real-core traffic test",
            binaries_dir().display()
        );
        return;
    };

    for origin in [CustomOrigin::Provider, CustomOrigin::User] {
        // 1. Start mock relays on localhost
        let primary_relay = MockRelay::start("primary", true);
        let fallback_relay = MockRelay::start("fallback", true);
        let decoy_port = 1; // unreachable port for decoy outbound

        // 2. Allocate free ports for Kasumi inbounds
        let (socks_port, http_port, force_port) = allocate_kasumi_inbound_ports();
        let settings = AdvancedSettings {
            local_socks_port: Some(socks_port),
            local_http_port: Some(http_port),
            ..AdvancedSettings::default()
        };

        let profile = build_synthetic_custom_profile(
            decoy_port,
            primary_relay.port,
            fallback_relay.port,
            origin,
        );
        let probe = build_xray_probe_config(&profile, &settings, &[])
            .unwrap_or_else(|e| panic!("build probe config for {origin:?} failed: {e}"));

        // 3. Write temp config and spawn Xray core with stderr captured to a log file
        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let cfg_path = temp_dir.path().join("xray_test.json");
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&probe.config).unwrap())
            .expect("write test config");

        let log_path = temp_dir.path().join("xray_test.log");
        let log_file = std::fs::File::create(&log_path).expect("create test log file");
        let log_file_err = log_file.try_clone().expect("clone log file");

        let child = Command::new(&xray_bin)
            .arg("run")
            .arg("-config")
            .arg(&cfg_path)
            .env("XRAY_LOCATION_ASSET", binaries_dir())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("spawn xray child process");

        let mut guard = ChildGuard(Some(child));

        // 4. Wait for Xray force-in port to be listening (bounded timeout <= 3s)
        let start = Instant::now();
        let mut ready = false;
        while start.elapsed() < Duration::from_secs(3) {
            if TcpStream::connect(format!("127.0.0.1:{force_port}")).is_ok() {
                ready = true;
                break;
            }
            if let Ok(Some(status)) = guard.0.as_mut().unwrap().try_wait() {
                let tail = read_log_tail(&log_path, 40);
                panic!("xray exited prematurely with {status}:\n{tail}");
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            ready,
            "xray did not become ready on force-in port {force_port} within 3s for {origin:?}.\nLog tail:\n{}",
            read_log_tail(&log_path, 40)
        );

        // 5. Send application request through Kasumi's generated force-in port until expected marker
        let resp = wait_for_traffic_marker(
            &mut guard,
            force_port,
            "OK node=primary",
            &log_path,
            Duration::from_secs(15),
        );
        assert!(
            resp.contains("OK node=primary"),
            "expected traffic routed to healthy primary node for {origin:?}, got response:\n{resp}"
        );
        assert!(
            primary_relay.requests_served.load(Ordering::SeqCst) > 0,
            "primary relay must have served requests for {origin:?}"
        );
    }
}

#[test]
fn test_real_xray_traffic_fallback_transition_when_primary_fails() {
    let Some(xray_bin) = find_xray_binary() else {
        eprintln!(
            "no staged xray binary found in KASUMI_XRAY_BIN or {}: skipping real-core traffic test",
            binaries_dir().display()
        );
        return;
    };

    for origin in [CustomOrigin::Provider, CustomOrigin::User] {
        // 1. Primary starts unhealthy (fails health probe and connection), fallback starts healthy
        let primary_relay = MockRelay::start("primary", false);
        let fallback_relay = MockRelay::start("fallback", true);
        let decoy_port = 1;

        let (socks_port, http_port, force_port) = allocate_kasumi_inbound_ports();
        let settings = AdvancedSettings {
            local_socks_port: Some(socks_port),
            local_http_port: Some(http_port),
            ..AdvancedSettings::default()
        };

        let profile = build_synthetic_custom_profile(
            decoy_port,
            primary_relay.port,
            fallback_relay.port,
            origin,
        );
        let probe = build_xray_probe_config(&profile, &settings, &[])
            .unwrap_or_else(|e| panic!("build probe config for {origin:?} failed: {e}"));

        let temp_dir = tempfile::tempdir().expect("create tempdir");
        let cfg_path = temp_dir.path().join("xray_fallback_test.json");
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&probe.config).unwrap())
            .expect("write test config");

        let log_path = temp_dir.path().join("xray_fallback_test.log");
        let log_file = std::fs::File::create(&log_path).expect("create fallback test log file");
        let log_file_err = log_file.try_clone().expect("clone log file");

        let child = Command::new(&xray_bin)
            .arg("run")
            .arg("-config")
            .arg(&cfg_path)
            .env("XRAY_LOCATION_ASSET", binaries_dir())
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file_err))
            .spawn()
            .expect("spawn xray child process");

        let mut guard = ChildGuard(Some(child));

        let start = Instant::now();
        let mut ready = false;
        while start.elapsed() < Duration::from_secs(3) {
            if TcpStream::connect(format!("127.0.0.1:{force_port}")).is_ok() {
                ready = true;
                break;
            }
            if let Ok(Some(status)) = guard.0.as_mut().unwrap().try_wait() {
                let tail = read_log_tail(&log_path, 40);
                panic!("xray exited prematurely with {status}:\n{tail}");
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(
            ready,
            "xray did not become ready on force-in port {force_port} within 3s for {origin:?}.\nLog tail:\n{}",
            read_log_tail(&log_path, 40)
        );

        // Send request through force-in port until expected marker is observed
        let resp = wait_for_traffic_marker(
            &mut guard,
            force_port,
            "OK node=fallback",
            &log_path,
            Duration::from_secs(15),
        );
        assert!(
            resp.contains("OK node=fallback"),
            "expected traffic routed to fallback node via virtual loopback transition for {origin:?}, got response:\n{resp}"
        );
        assert!(
            fallback_relay.requests_served.load(Ordering::SeqCst) > 0,
            "fallback relay must have served requests for {origin:?}"
        );
    }
}
