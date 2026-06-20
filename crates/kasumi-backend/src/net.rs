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
}

#[derive(Debug, Clone, Default)]
pub struct FetchUrlOptions {
    pub mode: FetchMode,
    pub proxy: Option<ProxyStatus>,
    pub user_agent: Option<String>,
    /// Skip TLS certificate verification.
    pub allow_insecure: bool,
    pub timeout: Option<Duration>,
}

fn socks_url(port: u16) -> String {
    format!("socks5h://127.0.0.1:{port}")
}

async fn fetch_once(
    url: &str,
    proxy: Option<String>,
    user_agent: Option<&str>,
    allow_insecure: bool,
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    let mut builder = reqwest::Client::builder().timeout(timeout);
    if let Some(p) = proxy {
        builder = builder.proxy(reqwest::Proxy::all(&p)?);
    }
    if allow_insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(ua) = user_agent {
        builder = builder.user_agent(ua);
    }
    let client = builder.build()?;
    let res = client.get(url).send().await?;
    if !res.status().is_success() {
        anyhow::bail!("HTTP {}", res.status().as_u16());
    }
    Ok(res.bytes().await?.to_vec())
}

/// Fetch a URL honoring the proxy mode. `Auto` tries the proxy when one is running
/// and falls back to direct; `Proxy` requires it; `Direct` never uses it.
pub async fn fetch_url(url: &str, opts: FetchUrlOptions) -> anyhow::Result<Vec<u8>> {
    let timeout = opts.timeout.unwrap_or(Duration::from_secs(30));
    let ua = opts.user_agent.as_deref();
    let running = opts.proxy.map(|p| p.running).unwrap_or(false);
    let try_proxy = opts.mode == FetchMode::Proxy || (opts.mode == FetchMode::Auto && running);

    if try_proxy {
        let proxy = opts.proxy.filter(|p| p.running);
        let Some(proxy) = proxy else {
            anyhow::bail!("proxy not running");
        };
        match fetch_once(
            url,
            Some(socks_url(proxy.socks_port)),
            ua,
            opts.allow_insecure,
            timeout,
        )
        .await
        {
            Ok(body) => return Ok(body),
            Err(err) => {
                if opts.mode == FetchMode::Proxy {
                    return Err(err);
                }
            }
        }
    }

    fetch_once(url, None, ua, opts.allow_insecure, timeout).await
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
            {
                if let Ok(port) = u16::from_str_radix(hex, 16) {
                    ports.insert(port);
                }
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
}
