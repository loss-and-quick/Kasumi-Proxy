//! DNS/address helpers shared by the desktop data-path (`singbox` + `routing`), so
//! the proxy-server bypass resolution lives in one place.

/// Resolve a host (domain or literal IP) to its IPs, or `[]` on failure.
pub async fn resolve_ips(host: &str) -> Vec<String> {
    match tokio::net::lookup_host((host, 0u16)).await {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Host-route CIDR for a single address (`/32` v4, `/128` v6).
pub fn cidr(ip: &str) -> String {
    if ip.contains(':') {
        format!("{ip}/128")
    } else {
        format!("{ip}/32")
    }
}

/// Whether a string is a bare IPv4/IPv6 literal (not a domain).
pub fn is_literal_ip(addr: &str) -> bool {
    addr.contains(':')
        || (!addr.is_empty() && addr.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_picks_family() {
        assert_eq!(cidr("1.2.3.4"), "1.2.3.4/32");
        assert_eq!(cidr("2001:db8::1"), "2001:db8::1/128");
    }

    #[test]
    fn literal_ip_detection() {
        assert!(is_literal_ip("8.8.8.8"));
        assert!(is_literal_ip("::1"));
        assert!(!is_literal_ip("dns.google"));
        assert!(!is_literal_ip(""));
    }

    #[tokio::test]
    async fn resolve_localhost_yields_loopback() {
        let ips = resolve_ips("localhost").await;
        assert!(ips.iter().any(|ip| ip == "127.0.0.1" || ip == "::1"));
    }
}
