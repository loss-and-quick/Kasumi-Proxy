//! Network primitives: proxy-aware HTTP fetch (subscription/asset downloads),
//! local-port discovery from `/proc/net/tcp`, and a TCP-connect latency probe.

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use kasumi_core::contract::FetchMode;
use reqwest::cookie::{CookieStore, Jar};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
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
    /// Cookies kept across fetches, keyed by host. A jar holding cookies for the URL
    /// replaces a `Cookie` in `headers`, as OkHttp's jar does for Happ.
    pub cookie_jar: Option<Arc<Jar>>,
    /// Resolve the host to IPv4 addresses only.
    pub ipv4_only: bool,
    /// Offer only gzip, as OkHttp does, instead of every supported encoding.
    pub gzip_only: bool,
    /// Offer HTTP/2 in TLS ALPN (`h2, http/1.1`), as OkHttp does; otherwise only
    /// HTTP/1.1 is offered. Plain `http://` stays on HTTP/1.1 either way.
    pub http2: bool,
    /// Write HTTP/1.1 header names in title case (`User-Agent`, `X-Hwid`) instead of
    /// lower case. OkHttp sends names as spelled (`User-agent`, `X-HWID`); hyper can't,
    /// as the case map it would need is private to it. Title case still matches the
    /// `Host`, `Connection` and `Accept-Encoding` OkHttp writes. HTTP/2 always sends
    /// lower case.
    pub title_case_headers: bool,
    /// Follow a redirect only to a public https host (a provider-chosen URL).
    pub redirect_guard: bool,
}

/// Most redirects one fetch follows, as reqwest's default policy.
const MAX_REDIRECTS: usize = 10;

fn guarded_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        match happ_sub::meta::validate_url_safety(attempt.url().as_str(), true) {
            Ok(()) => attempt.follow(),
            Err(why) => attempt.error(format!("redirect refused: {why}")),
        }
    })
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

/// A resolver that drops every IPv6 address.
struct Ipv4Only;

impl Resolve for Ipv4Only {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let v4: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(SocketAddr::is_ipv4)
                .collect();
            if v4.is_empty() {
                return Err(format!("{} has no IPv4 address", name.as_str()).into());
            }
            Ok(Box::new(v4.into_iter()) as Addrs)
        })
    }
}

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
    if opts.gzip_only {
        builder = builder.no_brotli().no_deflate();
    }
    if !opts.http2 {
        builder = builder.http1_only();
    }
    if opts.title_case_headers {
        builder = builder.http1_title_case_headers();
    }
    if opts.ipv4_only {
        builder = builder.dns_resolver(Arc::new(Ipv4Only));
    }
    if opts.redirect_guard {
        builder = builder.redirect(guarded_redirects());
    }
    // reqwest keeps a manual `Cookie` and skips the jar; OkHttp, which Happ uses, sends
    // the jar's cookies instead whenever it has some for the URL.
    let jar_has_cookies = match (&opts.cookie_jar, reqwest::Url::parse(url)) {
        (Some(jar), Ok(u)) => jar.cookies(&u).is_some(),
        _ => false,
    };
    if let Some(jar) = &opts.cookie_jar {
        builder = builder.cookie_provider(jar.clone());
    }
    let client = builder.build()?;
    let mut req = client.get(url);
    for (name, value) in &opts.headers {
        if jar_has_cookies && name.eq_ignore_ascii_case("cookie") {
            continue;
        }
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
    let base = reserve(&used, &mut leased_ports().lock().unwrap(), start, span);
    PortLease { base, span }
}

/// Record in `leased` the first `span` consecutive ports from `start` that are in
/// neither `used` nor `leased`, and return the first. With none free, `start`.
fn reserve(used: &HashSet<u16>, leased: &mut HashSet<u16>, start: u16, span: u16) -> u16 {
    let mut port = start;
    while port <= 65000 {
        if (0..span).all(|i| !used.contains(&(port + i)) && !leased.contains(&(port + i))) {
            break;
        }
        port += 1;
    }
    let base = if port <= 65000 { port } else { start };
    for i in 0..span {
        leased.insert(base + i);
    }
    base
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
    use crate::testutil::{fixture_response, http_response, serve, serve_tls};

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
    async fn tcp_ping_fails_when_nothing_accepts() {
        // A socket bound but never put into listen() refuses connections, and
        // holding it keeps the port from being rebound by a concurrent test.
        // Refusal and timeout both map to `None`, and neither needs the network.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = socket.local_addr().unwrap().port();
        let ms = tcp_ping("127.0.0.1", port, Duration::from_millis(300)).await;
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

    /// Header lines of a raw request head, lower-cased names, in wire order.
    fn header_lines(head: &str) -> Vec<(String, String)> {
        head.lines()
            .skip(1)
            .filter_map(|l| l.split_once(": "))
            .map(|(n, v)| (n.to_ascii_lowercase(), v.to_owned()))
            .collect()
    }

    #[tokio::test]
    async fn identity_headers_on_wire() {
        let (base, requests) = serve(vec![http_response(200, &[], b"ok")]).await;
        let headers: Vec<(String, String)> = [
            ("Connection", "close"),
            ("User-agent", "Happ/test"),
            ("X-Device-Locale", "ru"),
            ("X-HWID", "0123456789abcdef"),
            ("X-Device-OS", "Android"),
        ]
        .map(|(n, v)| (n.into(), v.into()))
        .into();
        let opts = FetchUrlOptions {
            headers: headers.clone(),
            gzip_only: true,
            ..direct()
        };
        fetch(&base, opts).await.unwrap();
        let sent = header_lines(&requests.lock().unwrap()[0]);
        let ours: Vec<(String, String)> = sent
            .iter()
            .filter(|(n, _)| headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(n)))
            .cloned()
            .collect();
        let want: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_ascii_lowercase(), v.clone()))
            .collect();
        assert_eq!(ours, want, "same headers, same order");
        let enc = sent.iter().find(|(n, _)| n == "accept-encoding").unwrap();
        assert_eq!(enc.1, "gzip");
    }

    fn happ_like(http2: bool) -> FetchUrlOptions {
        FetchUrlOptions {
            headers: vec![
                ("Connection".into(), "close".into()),
                ("User-agent".into(), "Happ/test".into()),
            ],
            gzip_only: true,
            http2,
            // The test server's certificate is self-signed.
            allow_insecure: true,
            ..direct()
        }
    }

    #[tokio::test]
    async fn http2_is_agreed_over_alpn_when_offered() {
        let (base, requests) = serve_tls(b"ok").await;
        let res = fetch(&format!("{base}/s"), happ_like(true)).await.unwrap();
        assert_eq!(res.body, b"ok");
        let seen = requests.lock().unwrap()[0].clone();
        assert_eq!(seen.alpn.as_deref(), Some("h2"));
        assert_eq!(seen.version, "HTTP/2");
        // HTTP/2 has no connection-level headers; `Connection: close` is dropped,
        // as OkHttp drops it.
        assert!(seen.headers.contains(&"user-agent".to_string()), "{seen:?}");
        assert!(
            !seen.headers.contains(&"connection".to_string()),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn http1_stays_when_http2_is_not_offered() {
        let (base, requests) = serve_tls(b"ok").await;
        let res = fetch(&format!("{base}/s"), happ_like(false)).await.unwrap();
        assert_eq!(res.body, b"ok");
        let seen = requests.lock().unwrap()[0].clone();
        assert_eq!(seen.alpn.as_deref(), Some("http/1.1"));
        assert_eq!(seen.version, "HTTP/1.1");
        assert!(
            seen.headers
                .iter()
                .any(|h| h.eq_ignore_ascii_case("connection"))
        );
    }

    #[tokio::test]
    async fn plain_http_stays_on_http1_with_http2_offered() {
        let (base, requests) = serve(vec![http_response(200, &[], b"ok")]).await;
        let res = fetch(&format!("{base}/s"), happ_like(true)).await.unwrap();
        assert_eq!(res.body, b"ok");
        assert!(requests.lock().unwrap()[0].starts_with("GET /s HTTP/1.1\r\n"));
    }

    /// Header names of a raw request head as written, in wire order.
    fn raw_names(head: &str) -> Vec<String> {
        head.lines()
            .skip(1)
            .filter_map(|l| l.split_once(": "))
            .map(|(n, _)| n.to_owned())
            .collect()
    }

    #[tokio::test]
    async fn header_case_is_lower_unless_title_case_is_asked() {
        let (base, requests) = serve(vec![http_response(200, &[], b"ok")]).await;
        let headers = vec![
            ("User-agent".to_string(), "Happ/test".to_string()),
            ("X-HWID".to_string(), "0123456789abcdef".to_string()),
        ];
        let plain = FetchUrlOptions {
            headers: headers.clone(),
            ..direct()
        };
        let titled = FetchUrlOptions {
            headers,
            title_case_headers: true,
            ..direct()
        };
        fetch(&base, plain).await.unwrap();
        fetch(&base, titled).await.unwrap();
        let heads = requests.lock().unwrap().clone();
        assert_eq!(
            raw_names(&heads[0]),
            ["user-agent", "x-hwid", "accept", "accept-encoding", "host"]
        );
        assert_eq!(
            raw_names(&heads[1]),
            ["User-Agent", "X-Hwid", "Accept", "Accept-Encoding", "Host"]
        );
    }

    #[tokio::test]
    async fn jar_cookies_replace_a_manual_cookie() {
        let set = http_response(200, &[("set-cookie", "session=abc; Path=/")], b"ok");
        let (base, requests) = serve(vec![
            http_response(200, &[], b"ok"),
            set,
            http_response(200, &[], b"ok"),
        ])
        .await;
        let jar = Arc::new(Jar::default());
        let opts = FetchUrlOptions {
            headers: vec![("Cookie".into(), "0123456789abcdef".into())],
            cookie_jar: Some(jar),
            ..direct()
        };
        for _ in 0..3 {
            fetch(&base, opts.clone()).await.unwrap();
        }
        let cookies: Vec<String> = requests
            .lock()
            .unwrap()
            .iter()
            .map(|head| {
                header_lines(head)
                    .into_iter()
                    .find(|(n, _)| n == "cookie")
                    .map(|(_, v)| v)
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(
            cookies,
            ["0123456789abcdef", "0123456789abcdef", "session=abc"]
        );
    }

    #[tokio::test]
    async fn ipv4_only_resolves_to_ipv4() {
        let (base, _) = serve(vec![http_response(200, &[], b"ok")]).await;
        let port = base.rsplit(':').next().unwrap();
        let opts = FetchUrlOptions {
            ipv4_only: true,
            ..direct()
        };
        let res = fetch(&format!("http://localhost:{port}/"), opts).await;
        assert_eq!(res.unwrap().body, b"ok");
    }

    #[test]
    fn dropping_a_lease_releases_its_ports() {
        // Far below any lease start, so no sibling test holds them.
        leased_ports().lock().unwrap().extend([7, 8]);
        drop(PortLease { base: 7, span: 2 });
        let leased = leased_ports().lock().unwrap();
        assert!(!leased.contains(&7) && !leased.contains(&8));
    }

    // The port scan and the process-wide lease set are left out here: other
    // processes bind ports and sibling tests lease them while this runs.
    #[test]
    fn reserve_skips_used_and_leased_ports_and_reuses_released_ones() {
        let used = HashSet::from([41001]);
        let mut leased = HashSet::new();
        assert_eq!(reserve(&used, &mut leased, 41000, 2), 41002);
        // A second lease anchored on the same start skips the held pair.
        assert_eq!(reserve(&used, &mut leased, 41000, 2), 41004);
        // What dropping the first lease does: its base is free again.
        leased.remove(&41002);
        leased.remove(&41003);
        assert_eq!(reserve(&used, &mut leased, 41000, 2), 41002);
    }
}
