//! String helpers shared by share-link parsing and the config builders.

use std::sync::LazyLock;

use percent_encoding::percent_decode_str;
use regex::Regex;

static ED_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[?&]ed=(\d+)").unwrap());
static EH_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[?&]eh=([^&]+)").unwrap());

pub struct WsEarlyData {
    pub path: String,
    pub ws_early_data: i64,
    pub ws_early_data_header: String,
}

/// Pull `ed=`/`eh=` out of a ws path into the early-data fields, returning the
/// cleaned path (first-match replace for each marker).
pub fn parse_ws_early_data(path: &str) -> WsEarlyData {
    let mut next = path.to_string();
    let mut ws_early_data = 0i64;
    let mut ws_early_data_header = String::new();

    if let Some(caps) = ED_RE.captures(&next) {
        ws_early_data = caps[1].parse().unwrap_or(0);
        ws_early_data_header = "Sec-WebSocket-Protocol".to_string();
        next = ED_RE.replace(&next, "").into_owned();
    }
    if let Some(caps) = EH_RE.captures(&next) {
        ws_early_data_header = percent_decode_str(&caps[1])
            .decode_utf8_lossy()
            .into_owned();
        next = EH_RE.replace(&next, "").into_owned();
    }

    // Tidy the leftover separators: collapse a leading `?&` and a doubled `&&`
    // (first occurrence each), then trim a trailing `?`/`&`.
    if let Some(i) = next.find("?&") {
        next.replace_range(i..i + 2, "?");
    }
    if let Some(i) = next.find("&&") {
        next.replace_range(i..i + 2, "&");
    }
    if next.ends_with('?') || next.ends_with('&') {
        next.pop();
    }

    WsEarlyData {
        path: next,
        ws_early_data,
        ws_early_data_header,
    }
}

/// Split a comma-separated string into trimmed non-empty parts, or `None`.
pub fn split_csv(s: &str) -> Option<Vec<String>> {
    let parts: Vec<String> = s
        .split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect();
    if parts.is_empty() { None } else { Some(parts) }
}

/// Split on commas or newlines into trimmed non-empty parts, or a fallback list.
pub fn split_list(v: &str, fallback: &[&str]) -> Vec<String> {
    let parts: Vec<String> = v
        .split([',', '\n'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect();
    if parts.is_empty() {
        fallback.iter().map(|s| s.to_string()).collect()
    } else {
        parts
    }
}

/// Split a PEM bundle into individual certificate blocks, or `None` if empty.
/// Falls back to the whole string when no BEGIN/END markers are present.
pub fn parse_pem_chain(pem: &str) -> Option<Vec<String>> {
    if pem.trim().is_empty() {
        return None;
    }
    static CERT_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----").unwrap()
    });
    let certs: Vec<String> = {
        let found: Vec<String> = CERT_RE
            .find_iter(pem)
            .map(|m| m.as_str().trim().to_string())
            .collect();
        if found.is_empty() {
            vec![pem.trim().to_string()]
        } else {
            found
        }
    }
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect();
    if certs.is_empty() { None } else { Some(certs) }
}

/// Re-attach `ed`/`eh` early-data params to a ws path (inverse of
/// [`parse_ws_early_data`]).
pub fn build_ws_path(path: &str, ws_early_data: i64, ws_early_data_header: &str) -> String {
    let base = if path.is_empty() { "/" } else { path };
    let mut pairs: Vec<(String, String)> = Vec::new();
    if ws_early_data > 0 {
        pairs.push(("ed".into(), ws_early_data.to_string()));
    }
    if !ws_early_data_header.is_empty() {
        pairs.push(("eh".into(), ws_early_data_header.to_string()));
    }
    if pairs.is_empty() {
        return base.to_string();
    }
    let qs: String = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    let sep = if base.contains('?') { '&' } else { '?' };
    format!("{base}{sep}{qs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ed_and_eh() {
        let w = parse_ws_early_data("/ws?ed=2048&eh=Sec-WebSocket-Protocol");
        assert_eq!(w.path, "/ws");
        assert_eq!(w.ws_early_data, 2048);
        assert_eq!(w.ws_early_data_header, "Sec-WebSocket-Protocol");
    }

    #[test]
    fn plain_path_untouched() {
        let w = parse_ws_early_data("/v");
        assert_eq!(w.path, "/v");
        assert_eq!(w.ws_early_data, 0);
        assert_eq!(w.ws_early_data_header, "");
    }

    #[test]
    fn ed_alone_defaults_the_header() {
        // `ed` without an explicit `eh` falls back to the standard ws header.
        let w = parse_ws_early_data("/p?ed=2048");
        assert_eq!(w.path, "/p");
        assert_eq!(w.ws_early_data, 2048);
        assert_eq!(w.ws_early_data_header, "Sec-WebSocket-Protocol");
    }

    #[test]
    fn eh_is_percent_decoded() {
        // The `eh` value carries a percent-encoded header name that must decode.
        let w = parse_ws_early_data("/p?ed=1&eh=a%2Fb");
        assert_eq!(w.path, "/p");
        assert_eq!(w.ws_early_data, 1);
        assert_eq!(w.ws_early_data_header, "a/b");
    }

    #[test]
    fn split_csv_trims_and_drops_empties() {
        assert_eq!(
            split_csv(" a , ,b "),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(split_csv(""), None);
        // A string of only separators has no non-empty parts.
        assert_eq!(split_csv(",, ,"), None);
    }

    #[test]
    fn split_list_splits_on_comma_and_newline_else_fallback() {
        assert_eq!(
            split_list("a,b\nc", &[]),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        // Empty input yields the fallback list verbatim.
        assert_eq!(
            split_list("  ", &["x", "y"]),
            vec!["x".to_string(), "y".to_string()]
        );
    }

    #[test]
    fn parse_pem_chain_splits_blocks_and_falls_back() {
        let two = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----";
        let certs = parse_pem_chain(two).unwrap();
        assert_eq!(certs.len(), 2);
        assert!(certs[0].contains("AAAA"));
        assert!(certs[1].contains("BBBB"));

        // No BEGIN/END markers → the whole (trimmed) string is the single cert.
        assert_eq!(
            parse_pem_chain("  raw-blob  "),
            Some(vec!["raw-blob".to_string()])
        );
        // Whitespace-only → nothing to return.
        assert_eq!(parse_pem_chain("   \n  "), None);
    }

    #[test]
    fn build_ws_path_handles_empty_separator_and_round_trips() {
        // An empty path normalises to "/".
        assert_eq!(build_ws_path("", 0, ""), "/");
        // A base that already has a query gets `&`, not a second `?`.
        let with_q = build_ws_path("/ws?token=abc", 100, "");
        assert!(with_q.starts_with("/ws?token=abc"));
        assert!(with_q.contains("&ed=100"));
        // build → parse restores both early-data fields and the clean path.
        let built = build_ws_path("/ws", 2048, "Sec-WebSocket-Protocol");
        let w = parse_ws_early_data(&built);
        assert_eq!(w.path, "/ws");
        assert_eq!(w.ws_early_data, 2048);
        assert_eq!(w.ws_early_data_header, "Sec-WebSocket-Protocol");
    }
}
