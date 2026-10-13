//! Network primitives: proxy-aware HTTP fetch (subscription/asset downloads),
//! local-port discovery from `/proc/net/tcp`, and a TCP-connect latency probe.

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use kasumi_core::contract::FetchMode;
use tokio::net::TcpStream;

use crate::fs::read_text;

/// Whether a core is up and the local ports to reach it on. The core exposes both
/// a SOCKS inbound (used for proxied fetches) and an HTTP inbound (the platform's
/// routing/bypass rules need its port too).
#[derive(Debug, Clone, Copy)]
pub struct ProxyStatus {
    pub running: bool,
    pub socks_port: u16,
    pub http_port: u16,
    /// The core's `force-in` socks port: routes straight to the proxy outbound,
    /// bypassing the geo rules. The app's own fetches use this so a subscription on
    /// a geo-`direct` host (e.g. a RU-hosted panel the local ISP blocks) still goes
    /// through the tunnel when proxy mode is wanted.
    pub force_port: u16,
}

#[derive(Debug, Clone, Default)]
pub struct FetchUrlOptions {
    pub mode: FetchMode,
    pub proxy: Option<ProxyStatus>,
    pub user_agent: Option<String>,
    /// Skip TLS certificate verification.
    pub allow_insecure: bool,
    pub timeout: Option<Duration>,
    /// Extra request headers, in wire order.
    pub headers: Vec<(String, String)>,
    /// Stop reading once the body exceeds this; `None` = unbounded.
    pub max_body_bytes: Option<usize>,
}

#[derive(Debug)]
pub struct FetchResponse {
    pub status: u16,
    /// Every header occurrence, values as lossy UTF-8.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub final_url: String,
}

/// A non-2xx reply, typed so callers can classify it.
#[derive(Debug)]
pub struct HttpStatusError(pub u16);

impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HTTP {}", self.0)
    }
}

impl std::error::Error for HttpStatusError {}

/// The body passed `max_body_bytes`.
#[derive(Debug)]
pub struct BodyTooLarge(pub usize);

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body exceeds {} bytes", self.0)
    }
}

impl std::error::Error for BodyTooLarge {}

fn socks_url(port: u16) -> String {
    format!("socks5h://127.0.0.1:{port}")
}

async fn fetch_once(
    url: &str,
    proxy: Option<String>,
    opts: &FetchUrlOptions,
    timeout: Duration,
) -> anyhow::Result<FetchResponse> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(p) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(&p)?);
    }
    if opts.allow_insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(ua) = &opts.user_agent {
        builder = builder.user_agent(ua);
    }
    let client = builder.build()?;
    let mut req = client.get(url);
    for (name, value) in &opts.headers {
        req = req.header(name, value);
    }
    let mut res = req.send().await?;
    let status = res.status().as_u16();
    if !res.status().is_success() {
        return Err(HttpStatusError(status).into());
    }
    let headers = res
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let final_url = res.url().to_string();
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await? {
        body.extend_from_slice(&chunk);
        if let Some(max) = opts.max_body_bytes
            && body.len() > max
        {
            return Err(BodyTooLarge(max).into());
        }
    }
    Ok(FetchResponse {
        status,
        headers,
        body,
        final_url,
    })
}

/// Fetch a URL honoring the proxy mode. `Auto` tries the proxy when one is running
/// and falls back to direct; `Proxy` requires it; `Direct` never uses it.
pub async fn fetch(url: &str, opts: FetchUrlOptions) -> anyhow::Result<FetchResponse> {
    let timeout = opts.timeout.unwrap_or(Duration::from_secs(30));
    let running = opts.proxy.map(|p| p.running).unwrap_or(false);
    let try_proxy = opts.mode == FetchMode::Proxy || (opts.mode == FetchMode::Auto && running);

    if try_proxy {
        let proxy = opts.proxy.filter(|p| p.running);
        let Some(proxy) = proxy else {
            anyhow::bail!("proxy not running");
        };
        // Force-proxy: route the attempt through `force-in`, which bypasses the geo
        // rules — a proxied fetch should always traverse the tunnel, never be sent
        // `direct` by a `geoip:ru`-style rule. Auto still falls back to direct below.
        match fetch_once(url, Some(socks_url(proxy.force_port)), &opts, timeout).await {
            Ok(res) => return Ok(res),
            Err(err) => {
                if opts.mode == FetchMode::Proxy {
                    return Err(err);
                }
            }
        }
    }

    fetch_once(url, None, &opts, timeout).await
}

/// [`fetch`] for callers that need only the body.
pub async fn fetch_url(url: &str, opts: FetchUrlOptions) -> anyhow::Result<Vec<u8>> {
    Ok(fetch(url, opts).await?.body)
}

/// Local TCP ports currently in use (LISTEN/connected), from `/proc/net/tcp{,6}`.
pub async fn used_ports() -> HashSet<u16> {
    let mut ports = HashSet::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Some(txt) = read_text(path).await else {
            continue;
        };
        // Column 1 is `local_address` as `HEXADDR:HEXPORT`.
        for line in txt.lines().skip(1) {
            if let Some(hex) = line
                .split_whitespace()
                .nth(1)
                .and_then(|a| a.split(':').nth(1))
                && let Ok(port) = u16::from_str_radix(hex, 16)
            {
                ports.insert(port);
            }
        }
    }
    ports
}

/// First free local port at or after `start` whose `span` consecutive ports are
/// all unused (so a test core's socks/http pair never collides).
pub async fn free_port(start: u16, span: u16) -> u16 {
    let used = used_ports().await;
    let mut port = start;
    while port <= 65000 {
        if (0..span).all(|i| !used.contains(&(port + i))) {
            return port;
        }
        port += 1;
    }
    start
}

fn leased_ports() -> &'static Mutex<HashSet<u16>> {
    static L: OnceLock<Mutex<HashSet<u16>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(HashSet::new()))
}

/// An RAII reservation of `span` consecutive local ports, released on drop.
pub struct PortLease {
    base: u16,
    span: u16,
}

impl PortLease {
    /// The first reserved port; the test core binds `base..base+span`.
    pub fn base(&self) -> u16 {
        self.base
    }
}

impl Drop for PortLease {
    fn drop(&mut self) {
        if let Ok(mut leased) = leased_ports().lock() {
            for i in 0..self.span {
                leased.remove(&(self.base + i));
            }
        }
    }
}

/// Atomically reserve `span` consecutive ports that are both free in
/// `/proc/net/tcp` AND not already leased by a concurrent in-flight test, then
/// hold them until the returned guard drops. Two guarantees `free_port` alone
/// can't give once WS commands dispatch concurrently: a port a sibling test is
/// about to bind is skipped (no TOCTOU collision), and a just-killed core's
/// TIME_WAIT port — still listed in `/proc` — won't be rebound under it.
pub async fn lease_ports(start: u16, span: u16) -> PortLease {
    let used = used_ports().await;
    let mut leased = leased_ports().lock().unwrap();
    let mut port = start;
    while port <= 65000 {
        if (0..span).all(|i| !used.contains(&(port + i)) && !leased.contains(&(port + i))) {
            for i in 0..span {
                leased.insert(port + i);
            }
            return PortLease { base: port, span };
        }
        port += 1;
    }
    for i in 0..span {
        leased.insert(start + i);
    }
    PortLease { base: start, span }
}

/// TCP-connect latency probe: round-trip ms to `host:port`, or `None` on
/// failure/timeout.
pub async fn tcp_ping(host: &str, port: u16, timeout: Duration) -> Option<u64> {
    let addr: SocketAddr = (host, port).to_socket_addrs().ok()?.next()?;
    let start = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{fixture_response, http_response, serve};

    #[tokio::test]
    async fn free_port_skips_a_used_port() {
        // Bind a real listener; its port must be reported used and skipped.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let taken = listener.local_addr().unwrap().port();
        let used = used_ports().await;
        assert!(used.contains(&taken), "bound port should show as used");
        // A span starting on the taken port can't begin there.
        let p = free_port(taken, 1).await;
        assert_ne!(p, taken);
    }

    #[tokio::test]
    async fn tcp_ping_reaches_a_live_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ms = tcp_ping("127.0.0.1", addr.port(), Duration::from_secs(2)).await;
        assert!(ms.is_some());
    }

    #[tokio::test]
    async fn tcp_ping_fails_on_unreachable_host() {
        // TEST-NET-1 (RFC 5737) is guaranteed unroutable, so the connect can't
        // succeed — it errors or times out, either way `None`. (A freed loopback
        // port would race a concurrent test that rebinds it.)
        let ms = tcp_ping("192.0.2.1", 80, Duration::from_millis(300)).await;
        assert!(ms.is_none());
    }

    #[tokio::test]
    async fn fetch_url_proxy_mode_requires_a_running_proxy() {
        // mode=Proxy with no proxy must fail fast, before any network attempt.
        let opts = FetchUrlOptions {
            mode: FetchMode::Proxy,
            ..Default::default()
        };
        let err = fetch_url("http://example.invalid/", opts)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("proxy not running"));

        // A proxy that isn't running is treated the same as none.
        let opts = FetchUrlOptions {
            mode: FetchMode::Proxy,
            proxy: Some(ProxyStatus {
                running: false,
                socks_port: 1080,
                http_port: 1081,
                force_port: 1082,
            }),
            ..Default::default()
        };
        let err = fetch_url("http://example.invalid/", opts)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("proxy not running"));
    }

    fn direct() -> FetchUrlOptions {
        FetchUrlOptions {
            mode: FetchMode::Direct,
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn fetch_returns_status_headers_body() {
        let (base, requests) = serve(vec![fixture_response("01-happ-full")]).await;
        let opts = FetchUrlOptions {
            headers: vec![("X-Probe".into(), "1".into())],
            ..direct()
        };
        let res = fetch(&format!("{base}/sub"), opts).await.unwrap();
        assert_eq!(res.status, 200);
        let header = |name: &str| {
            res.headers
                .iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(header("profile-update-interval"), ["1"]);
        assert_eq!(header("set-cookie").len(), 4);
        assert!(res.body.starts_with(b"dmxlc3M6Ly"));
        assert_eq!(res.final_url, format!("{base}/sub"));
        let sent = requests.lock().unwrap()[0].to_ascii_lowercase();
        assert!(sent.contains("x-probe: 1"), "{sent}");
    }

    #[tokio::test]
    async fn fetch_enforces_body_limit() {
        let (base, _) = serve(vec![http_response(200, &[], &[b'a'; 4096])]).await;
        let opts = FetchUrlOptions {
            max_body_bytes: Some(1024),
            ..direct()
        };
        let err = fetch(&base, opts).await.unwrap_err();
        assert!(err.to_string().contains("body exceeds 1024 bytes"), "{err}");

        let opts = FetchUrlOptions {
            max_body_bytes: Some(4096),
            ..direct()
        };
        assert_eq!(fetch(&base, opts).await.unwrap().body.len(), 4096);
    }

    #[tokio::test]
    async fn non_2xx_is_http_status_error() {
        let (base, _) = serve(vec![http_response(403, &[], b"denied")]).await;
        let err = fetch_url(&base, direct()).await.unwrap_err();
        assert_eq!(
            err.downcast_ref::<HttpStatusError>().map(|e| e.0),
            Some(403)
        );
        assert_eq!(err.to_string(), "HTTP 403");
    }

    #[tokio::test]
    async fn lease_ports_reserves_disjoint_ranges_and_releases_on_drop() {
        let l1 = lease_ports(41000, 2).await;
        let b1 = l1.base();
        assert!(b1 >= 41000);
        // A concurrent lease anchored on the same base skips the held pair.
        let l2 = lease_ports(b1, 2).await;
        assert!(l2.base() >= b1 + 2, "leases must not overlap");
        // Dropping l1 frees its ports; a fresh lease reclaims the same base
        // (l2 still holds its own range, so this isn't just landing anywhere).
        drop(l1);
        let l3 = lease_ports(b1, 2).await;
        assert_eq!(l3.base(), b1);
        drop(l2);
        drop(l3);
    }
}
