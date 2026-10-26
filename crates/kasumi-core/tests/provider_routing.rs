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
//! 6. When all balancer members are unreachable and the balancer has no fallbackTag,
//!    it fails over to the explicit default handler and terminates without infinite loopback
//!    recursion.

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

fn find_asset_dir() -> PathBuf {
    if let Ok(p) = std::env::var("KASUMI_XRAY_ASSET_DIR") {
        let path = PathBuf::from(p);
        if path.is_dir() {
            return path;
        }
    }
    binaries_dir()
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

        thread::sleep(Duration::from_millis(100));
    }

    let tail = read_log_tail(log_path, 40);
    panic!(
        "timed out after {:?} waiting for marker '{}'. Last resp: {:?}, Last err: {:?}.\nLog tail:\n{}",
        timeout, expected_marker, last_response, last_error, tail
    );
}

fn allocate_kasumi_inbound_ports() -> (u16, u16, u16) {
    let l1 = TcpListener::bind("127.0.0.1:0").expect("bind free socks port");
    let l2 = TcpListener::bind("127.0.0.1:0").expect("bind free http port");
    let p1 = l1.local_addr().unwrap().port();
    let p2 = l2.local_addr().unwrap().port();
    let p3 = force_socks_port(p1, p2);
    drop(l1);
    drop(l2);
    (p1, p2, p3)
}

struct MockRelay {
    pub port: u16,
    pub requests_served: Arc<AtomicUsize>,
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockRelay {
    pub fn start(node_id: &'static str, initial_healthy: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock relay port");
        let port = listener.local_addr().unwrap().port();
        listener
            .set_nonblocking(true)
            .expect("set nonblocking listener");

        let healthy = Arc::new(AtomicBool::new(initial_healthy));
        let running = Arc::new(AtomicBool::new(true));
        let requests_served = Arc::new(AtomicUsize::new(0));

        let h_clone = healthy.clone();
        let r_clone = running.clone();
        let cnt_clone = requests_served.clone();

        let handle = thread::spawn(move || {
            while r_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let is_healthy = h_clone.load(Ordering::SeqCst);
                        let counter = cnt_clone.clone();
                        thread::spawn(move || {
                            handle_mock_connection(stream, is_healthy, node_id, counter);
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
            requests_served,
            running,
            handle: Some(handle),
        }
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
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
        let _ = stream.write_all(&[0x05, 0xff]);
        let _ = stream.flush();
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    if stream.write_all(&[0x05, 0x00]).is_err() {
        return;
    }
    let _ = stream.flush();

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

    let socks5_resp = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80];
    if stream.write_all(&socks5_resp).is_err() {
        return;
    }
    let _ = stream.flush();

    let mut buf = [0u8; 2048];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let req_str = String::from_utf8_lossy(&buf[..n]);
    if req_str.contains("GET /health") {
        let http_resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
        let _ = stream.write_all(http_resp.as_bytes());
        let _ = stream.flush();
        return;
    }

    req_counter.fetch_add(1, Ordering::SeqCst);
    let body = format!("OK node={node_id}");
    let http_resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(http_resp.as_bytes());
    let _ = stream.flush();
}

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

fn build_synthetic_custom_profile(
    decoy_port: u16,
    primary_port: u16,
    fallback_port: u16,
    origin: CustomOrigin,
) -> Profile {
    let raw = json!({
        "outbounds": [
            {
                "tag": "decoy-broken",
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
        "meta": { "id": "test-synthetic", "remarks": "Synthetic Provider", "groupId": "g-test" },
        "raw": raw.to_string(),
        "origin": origin,
    }))
    .unwrap()
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

#[test]
fn test_emitted_config_default_target_is_not_first_decoy() {
    let profile = build_synthetic_provider_profile(1, 10801, 10802);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[])
        .expect("build probe config for synthetic provider");

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
        let primary_relay = MockRelay::start("primary", true);
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
            .env("XRAY_LOCATION_ASSET", find_asset_dir())
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
            .env("XRAY_LOCATION_ASSET", find_asset_dir())
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

        let resp = wait_for_traffic_marker(
            &mut guard,
            force_port,
            "OK node=fallback",
            &log_path,
            Duration::from_secs(15),
        );
        assert!(
            resp.contains("OK node=fallback"),
            "expected traffic routed to healthy fallback node for {origin:?}, got response:\n{resp}"
        );
        assert!(
            fallback_relay.requests_served.load(Ordering::SeqCst) > 0,
            "fallback relay must have served requests for {origin:?}"
        );
    }
}

#[test]
fn test_real_xray_traffic_unreachable_balancer_without_fallback_terminates_without_recursion() {
    let Some(xray_bin) = find_xray_binary() else {
        eprintln!(
            "no staged xray binary found in KASUMI_XRAY_BIN or {}: skipping real-core traffic test",
            binaries_dir().display()
        );
        return;
    };

    // A profile with unreachable balancer members and NO fallbackTag on the balancer.
    // In PR 415, empty balancer selection dispatched to default handler = proxy loopback,
    // causing an infinite loop (15k re-entries, 4GB RSS).
    // With explicit default fallback, empty balancer selection routes to default_handler (outbound 0),
    // failing the connection cleanly without loopback recursion.
    let (socks_port, http_port, force_port) = allocate_kasumi_inbound_ports();
    let settings = AdvancedSettings {
        local_socks_port: Some(socks_port),
        local_http_port: Some(http_port),
        ..AdvancedSettings::default()
    };

    let raw = json!({
        "outbounds": [
            {
                "tag": "decoy-dead",
                "protocol": "socks",
                "settings": {
                    "servers": [{ "address": "127.0.0.1", "port": 1 }]
                }
            },
            {
                "tag": "node-unreachable-1",
                "protocol": "socks",
                "settings": {
                    "servers": [{ "address": "127.0.0.1", "port": 1 }]
                }
            },
            {
                "tag": "node-unreachable-2",
                "protocol": "socks",
                "settings": {
                    "servers": [{ "address": "127.0.0.1", "port": 2 }]
                }
            }
        ],
        "routing": {
            "balancers": [
                {
                    "tag": "balancer-dead",
                    "selector": ["node-unreachable-"],
                    "strategy": { "type": "leastLoad" }
                    // NO fallbackTag! Explicit fallback becomes decoy-dead
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "balancer-dead"
                }
            ]
        },
        "burstObservatory": {
            "pingConfig": {
                "destination": PROBE_URL,
                "interval": "10s",
                "timeout": "1s",
                "sampling": 1
            },
            "subjectSelector": ["node-unreachable-1", "node-unreachable-2"]
        }
    });

    let profile: Profile = serde_json::from_value(json!({
        "protocol": "custom",
        "meta": { "id": "test-recursion", "remarks": "Recursion Test", "groupId": "g-test" },
        "raw": raw.to_string(),
        "origin": "provider",
    }))
    .unwrap();

    let mut probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe config");
    probe.config["log"] = json!({ "loglevel": "info" });

    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let cfg_path = temp_dir.path().join("xray_recursion_test.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&probe.config).unwrap())
        .expect("write test config");

    let log_path = temp_dir.path().join("xray_recursion_test.log");
    let log_file = std::fs::File::create(&log_path).expect("create log file");
    let log_file_err = log_file.try_clone().expect("clone log file");

    let child = Command::new(&xray_bin)
        .arg("run")
        .arg("-config")
        .arg(&cfg_path)
        .env("XRAY_LOCATION_ASSET", find_asset_dir())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .spawn()
        .expect("spawn xray child process");

    let mut guard = ChildGuard(Some(child));

    // Wait for Xray force-in port to be listening (bounded timeout <= 3s)
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
        "xray did not become ready on force-in port {force_port} within 3s.\nLog tail:\n{}",
        read_log_tail(&log_path, 40)
    );

    // Send a request through force-in port. Must complete/fail within bounded time (<= 3s)
    let req_start = Instant::now();
    let res = send_socks5_http_request(force_port, "target.example", 80, "/test");
    let duration = req_start.elapsed();

    // The request should fail/close because all nodes are unreachable, and fail quickly
    assert!(
        duration < Duration::from_secs(5),
        "request took too long: {duration:?}"
    );
    // When the proxy fails to connect to the upstream, it closes the connection (returns EOF -> empty resp or Err)
    if let Ok(ref s) = res {
        assert!(
            s.is_empty(),
            "expected empty response on failed upstream, got: {s}"
        );
    }

    // At info level Xray records the force-in hand-off, the loopback context
    // selection, and the balancer fallback. The old implicit default re-entered
    // `proxy` indefinitely; an explicit fallback can select this context once.
    let log_content = std::fs::read_to_string(&log_path).unwrap_or_default();
    let force_to_proxy = log_content
        .lines()
        .filter(|line| line.contains("taking detour [proxy]"))
        .count();
    let proxy_select_routes = log_content
        .lines()
        .filter(|line| line.contains("[proxy-select ->"))
        .count();
    assert!(
        force_to_proxy >= 1 && proxy_select_routes >= 1,
        "expected info-level force-in and proxy-select routing records. Log:\n{log_content}"
    );
    assert!(
        force_to_proxy <= 1 && proxy_select_routes <= 1,
        "expected no proxy re-entry, but saw {force_to_proxy} proxy detours and {proxy_select_routes} proxy-select routes. Log:\n{log_content}"
    );
    assert!(
        log_content.contains("app/router: fallback to ["),
        "expected Xray to record the explicit balancer fallback. Log:\n{log_content}"
    );
}

fn server(tag: &str) -> Value {
    json!({
        "tag": tag, "protocol": "vless",
        "settings": { "vnext": [{ "address": "127.0.0.1", "port": 443,
            "users": [{ "id": "11111111-1111-1111-1111-111111111111", "encryption": "none" }] }] },
        "streamSettings": { "network": "tcp", "security": "tls" }
    })
}

fn freedom(tag: &str) -> Value {
    json!({ "tag": tag, "protocol": "freedom" })
}

fn custom_profile_from_json(raw: Value) -> Profile {
    serde_json::from_value(json!({
        "protocol": "custom",
        "meta": { "id": "test-costs", "remarks": "Test Costs", "groupId": "g-test" },
        "raw": raw.to_string(),
        "origin": CustomOrigin::Provider,
    }))
    .unwrap()
}

#[test]
fn leastload_costs_ordered_overlapping_substring_matches_rendered_as_opaque_tags() {
    let raw = json!({
        "outbounds": [
            server("prefix-node-a"),
            server("node-b"),
            server("node-ab"),
            server("unmatched"),
            freedom("direct")
        ],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["prefix-node-a", "node-b", "node-ab", "unmatched"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [
                            { "match": "node-a", "value": 2 },
                            { "match": "node", "value": 4 }
                        ]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["prefix-node-a", "node-b", "node-ab", "unmatched"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe");
    let balancers = probe.config["routing"]["balancers"]
        .as_array()
        .expect("balancers");
    let lb = &balancers[0];
    let costs = lb["strategy"]["settings"]["costs"]
        .as_array()
        .expect("costs");
    assert_eq!(costs.len(), 4);

    for entry in costs {
        assert_eq!(entry["regexp"], false);
        let m = entry["match"].as_str().unwrap();
        assert!(m.starts_with("ks-provider:"));
        assert!(m.ends_with(':'));
    }

    let values: Vec<f64> = costs.iter().map(|c| c["value"].as_f64().unwrap()).collect();
    assert_eq!(values, vec![2.0, 4.0, 2.0, 1.0]);
}

#[test]
fn leastload_costs_empty_match_and_no_match_default_to_weight_one() {
    let raw = json!({
        "outbounds": [server("node-a"), server("other"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node-a", "other"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [
                            { "match": "", "value": 9 },
                            { "match": "node", "value": 3 }
                        ]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-a", "other"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe");
    let lb = &probe.config["routing"]["balancers"][0];
    let costs = lb["strategy"]["settings"]["costs"]
        .as_array()
        .expect("costs");
    assert_eq!(costs.len(), 2);
    let values: Vec<f64> = costs.iter().map(|c| c["value"].as_f64().unwrap()).collect();
    assert_eq!(values, vec![3.0, 1.0]);
}

#[test]
fn leastload_costs_regex_explicit_and_numeric_auto_extraction_from_matched_portion() {
    let raw = json!({
        "outbounds": [
            server("node-99-cost-3.5"),
            server("node-a"),
            server("node-plain"),
            freedom("direct")
        ],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [
                            { "match": "cost-[0-9.]+", "regexp": true, "value": -1 },
                            { "match": "node-a", "value": 0.1 },
                            { "match": "node-plain", "value": 0 }
                        ]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe");
    let lb = &probe.config["routing"]["balancers"][0];
    let costs = lb["strategy"]["settings"]["costs"]
        .as_array()
        .expect("costs");
    assert_eq!(costs.len(), 3);
    assert_eq!(costs[0]["value"], 3.5);
    assert_eq!(costs[1]["value"], 0.1);
    assert_eq!(costs[2]["value"], 1);
}

#[test]
fn leastload_costs_ascii_regex_d_and_s_semantics_with_vertical_tab() {
    let raw = json!({
        "outbounds": [
            server("node\t7"),
            server("node\u{000b}7"),
            server("node 7"),
            server("node_7"),
            server("node-7"),
            freedom("direct")
        ],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [
                            { "match": "node\\s[0-9]", "regexp": true, "value": 2 },
                            { "match": "^\\w+$", "regexp": true, "value": 4 }
                        ]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe");
    let lb = &probe.config["routing"]["balancers"][0];
    let costs = lb["strategy"]["settings"]["costs"]
        .as_array()
        .expect("costs");
    assert_eq!(costs.len(), 5);
    assert_eq!(costs[0]["value"], 2);
    assert_eq!(costs[1]["value"], 1);
    assert_eq!(costs[2]["value"], 2);
    assert_eq!(costs[3]["value"], 4);
    assert_eq!(costs[4]["value"], 1);
}

#[test]
fn two_balancers_can_assign_different_costs_to_the_same_member() {
    let raw = json!({
        "outbounds": [server("node-shared"), freedom("direct")],
        "routing": {
            "balancers": [
                {
                    "tag": "lb-fast",
                    "selector": ["node-shared"],
                    "strategy": {
                        "type": "leastLoad",
                        "settings": { "costs": [{ "match": "node", "value": 5 }] }
                    },
                    "fallbackTag": "direct"
                },
                {
                    "tag": "lb-slow",
                    "selector": ["node-shared"],
                    "strategy": {
                        "type": "leastLoad",
                        "settings": { "costs": [{ "match": "node", "value": 10 }] }
                    },
                    "fallbackTag": "direct"
                }
            ],
            "rules": [
                { "inboundTag": ["socks-in"], "balancerTag": "lb-fast" },
                { "network": "tcp,udp", "balancerTag": "lb-slow" }
            ]
        },
        "observatory": {
            "subjectSelector": ["node-shared"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe");
    let balancers = probe.config["routing"]["balancers"]
        .as_array()
        .expect("balancers");
    assert_eq!(balancers.len(), 2);
    assert_eq!(balancers[0]["strategy"]["settings"]["costs"][0]["value"], 5);
    assert_eq!(
        balancers[1]["strategy"]["settings"]["costs"][0]["value"],
        10
    );
}

#[test]
fn leastload_costs_original_tags_with_prefix_collisions_rendered_prefix_free() {
    let raw = json!({
        "outbounds": [server("node-1"), server("node-10"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [
                            { "match": "node-10", "value": 50 },
                            { "match": "node-1", "value": 20 }
                        ]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe");
    let costs = probe.config["routing"]["balancers"][0]["strategy"]["settings"]["costs"]
        .as_array()
        .unwrap();
    assert_eq!(costs.len(), 2);
    assert_eq!(costs[0]["value"], 20);
    assert_eq!(costs[1]["value"], 50);
}

#[test]
fn anonymous_outbound_compiler_identity_not_persisted_and_evaluates_empty_for_costs() {
    let mut ob_anon = server("node-will-be-stripped");
    ob_anon.as_object_mut().unwrap().remove("tag");

    let raw = json!({
        "outbounds": [ob_anon, server("node-named")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node-named"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [
                            { "match": "unnamed", "value": 99 },
                            { "match": "node-named", "value": 42 }
                        ]
                    }
                },
                "fallbackTag": "node-named"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-named"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    // Compiler identities must not become source tags when a profile is stored.
    let sanitized = kasumi_core::custom_sanitize::sanitize_provider_xray(&raw).expect("sanitize");
    assert!(sanitized.outbounds[0].get("tag").is_none());

    let persisted = sanitized.into_provider_json();
    assert!(persisted["outbounds"][0].get("tag").is_none());

    let resanitized =
        kasumi_core::custom_sanitize::sanitize_provider_xray(&persisted).expect("resanitize");
    assert!(resanitized.outbounds[0].get("tag").is_none());

    let profile = custom_profile_from_json(persisted);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe");
    let costs = probe.config["routing"]["balancers"][0]["strategy"]["settings"]["costs"]
        .as_array()
        .unwrap();
    assert_eq!(costs.len(), 1);
    assert_eq!(costs[0]["value"], 42);
}

#[test]
fn explicit_empty_tag_outbound_persistence_and_selector_exclusion_roundtrip() {
    let mut ob_empty = server("node-empty");
    ob_empty["tag"] = "".into();

    let raw = json!({
        "outbounds": [ob_empty, server("node-named")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": [""],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [
                            { "match": "node-named", "value": 7 }
                        ]
                    }
                },
                "fallbackTag": "node-named"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-named"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    // 1. Sanitizer: explicit empty tag outbound is excluded from balancer selector
    let sanitized = kasumi_core::custom_sanitize::sanitize_provider_xray(&raw).expect("sanitize");
    let lb = sanitized
        .fragment
        .balancers
        .iter()
        .find(|b| b.tag == "lb")
        .unwrap();
    // Only "node-named" matched; "" was excluded from selector candidates
    assert_eq!(lb.members, vec!["node-named"]);

    // 2. Persisted JSON strips tag from explicit-empty tag outbound
    let persisted = sanitized.into_provider_json();
    assert!(persisted["outbounds"][0].get("tag").is_none());

    // 3. Re-sanitizing persisted JSON preserves untagged state and member set
    let resanitized =
        kasumi_core::custom_sanitize::sanitize_provider_xray(&persisted).expect("resanitize");
    let resanitized_lb = resanitized
        .fragment
        .balancers
        .iter()
        .find(|b| b.tag == "lb")
        .unwrap();
    assert_eq!(resanitized_lb.members, vec!["node-named"]);
    assert_eq!(resanitized.into_provider_json(), persisted);
}

#[test]
fn leastload_costs_render_and_reingest_are_stable_and_idempotent() {
    let raw = json!({
        "outbounds": [server("node-1"), server("node-2"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [{ "match": "node-1", "value": 5 }]
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe1 = build_xray_probe_config(&profile, &settings, &[]).expect("probe 1");
    let probe2 = build_xray_probe_config(&profile, &settings, &[]).expect("probe 2");
    assert_eq!(probe1.config, probe2.config);
}

#[test]
fn other_leastload_settings_are_retained_when_costs_are_rendered() {
    let raw = json!({
        "outbounds": [server("node-1"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [{ "match": "node-1", "value": 2 }],
                        "baselines": [100000000, 200000000],
                        "expected": 2,
                        "maxRTT": 500000000,
                        "tolerance": 0.05
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("probe");
    let strat_settings = &probe.config["routing"]["balancers"][0]["strategy"]["settings"];
    assert_eq!(strat_settings["expected"], 2);
    assert_eq!(strat_settings["maxRTT"], 500000000);
    assert_eq!(strat_settings["tolerance"], 0.05);
    assert_eq!(strat_settings["baselines"], json!([100000000, 200000000]));
    assert!(strat_settings["costs"].as_array().is_some());
}

#[test]
fn no_cost_leastload_balancer_is_unchanged() {
    let raw = json!({
        "outbounds": [server("node-1"), freedom("direct")],
        "routing": {
            "balancers": [{
                "tag": "lb",
                "selector": ["node-"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "expected": 1
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb" }]
        },
        "observatory": {
            "subjectSelector": ["node-"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let settings = AdvancedSettings::default();
    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("probe");
    let strat_settings = &probe.config["routing"]["balancers"][0]["strategy"]["settings"];
    assert!(strat_settings.get("costs").is_none());
}

#[test]
fn compiled_config_with_costs_accepted_by_pinned_xray() {
    let Some(xray_bin) = find_xray_binary() else {
        eprintln!(
            "no staged xray binary found in KASUMI_XRAY_BIN or {}: skipping real-core test",
            binaries_dir().display()
        );
        return;
    };

    let relay = MockRelay::start("costs-upstream", true);
    let raw = json!({
        "outbounds": [
            {
                "tag": "node-target",
                "protocol": "socks",
                "settings": {
                    "servers": [{ "address": "127.0.0.1", "port": relay.port }]
                }
            },
            freedom("direct")
        ],
        "routing": {
            "balancers": [{
                "tag": "lb-costs",
                "selector": ["node-target"],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        "costs": [
                            { "match": "node-target", "value": 2.5 }
                        ],
                        "expected": 1
                    }
                },
                "fallbackTag": "direct"
            }],
            "rules": [{ "network": "tcp,udp", "balancerTag": "lb-costs" }]
        },
        "observatory": {
            "subjectSelector": ["node-target"],
            "probeURL": "https://example.org/generate_204",
            "probeInterval": "10s"
        }
    });

    let profile = custom_profile_from_json(raw);
    let (socks_port, http_port, force_port) = allocate_kasumi_inbound_ports();
    let settings = AdvancedSettings {
        local_socks_port: Some(socks_port),
        local_http_port: Some(http_port),
        ..AdvancedSettings::default()
    };

    let probe = build_xray_probe_config(&profile, &settings, &[]).expect("build probe config");

    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let cfg_path = temp_dir.path().join("xray_costs_test.json");
    std::fs::write(&cfg_path, serde_json::to_vec_pretty(&probe.config).unwrap())
        .expect("write test config");

    let log_path = temp_dir.path().join("xray_costs_test.log");
    let log_file = std::fs::File::create(&log_path).expect("create test log file");
    let log_file_err = log_file.try_clone().expect("clone log file");

    let child = Command::new(&xray_bin)
        .arg("run")
        .arg("-config")
        .arg(&cfg_path)
        .env("XRAY_LOCATION_ASSET", find_asset_dir())
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
        "xray with leastLoad costs did not become ready within 3s. Log:\n{}",
        read_log_tail(&log_path, 40)
    );
}
