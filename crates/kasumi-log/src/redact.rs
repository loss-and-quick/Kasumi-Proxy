//! Keeping credentials out of the log.
//!
//! A proxy configuration is mostly secrets. A subscription URL is a bearer token, a
//! profile carries a password or a UUID in its path, and both travel inside the
//! error chains that `anyhow` and `reqwest` build — which is exactly what gets
//! logged when a fetch fails. Redaction therefore happens at the call site that
//! holds the sensitive value, and the helpers here are deliberately narrow: they
//! strip what they know is secret and leave the rest of the message readable, since
//! a log that says "invalid URL" helps nobody.

/// A URL safe to log: no userinfo, no query, no fragment. Enough to tell *which*
/// server was talked to, useless to anyone who finds the log file.
///
/// `https://user:pass@sub.example.com/list?token=abc#x`
///     → `https://sub.example.com/list`
pub fn url(raw: &str) -> String {
    let raw = raw.trim();
    let Some((scheme, rest)) = raw.split_once("://") else {
        // Not a URL: fall back to dropping the query tail, which is where a bare
        // token argument usually sits.
        return query_free(raw).into_owned();
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // Everything before the last `@` is userinfo; hostnames cannot contain one.
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    let path = path.split(['?', '#']).next().unwrap_or("");
    format!("{scheme}://{authority}{path}")
}

/// Just the scheme, host and port of a URL — for "which endpoint answered" lines
/// where even the path is noise.
pub fn origin(raw: &str) -> String {
    let raw = raw.trim();
    let Some((scheme, rest)) = raw.split_once("://") else {
        return query_free(raw).into_owned();
    };
    let authority = match rest.find('/') {
        Some(i) => &rest[..i],
        None => rest,
    };
    let authority = match authority.rsplit_once('@') {
        Some((_, host)) => host,
        None => authority,
    };
    format!("{scheme}://{authority}")
}

/// Everything before the first `?` or `#`. Use for free-form text that may carry a
/// token as an argument (`...?token=…`, `#access_token=…`).
pub fn query_free(raw: &str) -> std::borrow::Cow<'_, str> {
    let cut = raw.find(['?', '#']).unwrap_or(raw.len());
    std::borrow::Cow::Borrowed(&raw[..cut])
}

/// Redact every URL inside free-form text. An error chain from a fetch carries the
/// URL that failed, and the chain is the most valuable thing to log about a failed
/// fetch — so it is logged whole, with each URL replaced by [`url`]. Matches `http://`
/// and `https://` case-insensitively and stops at the next whitespace, which covers
/// both a stored subscription link and the normalised form a client library echoes.
pub fn in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = find_scheme(rest) {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        // Never split inside the scheme itself, whatever the text looks like.
        let end = tail
            .find(char::is_whitespace)
            .unwrap_or(tail.len())
            .max(SCHEME_HTTPS.len());
        let (token, remainder) = tail.split_at(end);
        let (link, punctuation) = split_trailing_punctuation(token);
        out.push_str(&url(link));
        out.push_str(punctuation);
        rest = remainder;
    }
    out.push_str(rest);
    out
}

const SCHEME_HTTP: &str = "http://";
const SCHEME_HTTPS: &str = "https://";

fn find_scheme(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    match (lower.find(SCHEME_HTTP), lower.find(SCHEME_HTTPS)) {
        (Some(http), Some(https)) => Some(http.min(https)),
        (Some(found), None) | (None, Some(found)) => Some(found),
        (None, None) => None,
    }
}

/// Punctuation that ends the URL rather than belonging to it: error messages wrap
/// URLs in brackets and quotes.
fn split_trailing_punctuation(token: &str) -> (&str, &str) {
    let end = token.trim_end_matches(['.', ',', ';', ':', ')', ']', '\'', '"']);
    token.split_at(end.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_userinfo_query_and_fragment() {
        assert_eq!(
            url("https://user:pass@sub.example.com:8443/list?token=abc#frag"),
            "https://sub.example.com:8443/list"
        );
    }

    #[test]
    fn keeps_a_url_without_secrets_unchanged() {
        assert_eq!(
            url("https://example.com/sub/link"),
            "https://example.com/sub/link"
        );
        assert_eq!(url("https://example.com"), "https://example.com");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            url("  https://example.com/a?b=c  "),
            "https://example.com/a"
        );
    }

    #[test]
    fn non_url_text_only_loses_its_query() {
        assert_eq!(url("plain text?token=abc"), "plain text");
        assert_eq!(origin("plain text"), "plain text");
    }

    #[test]
    fn origin_drops_the_path() {
        assert_eq!(
            origin("https://user@sub.example.com/list?token=abc"),
            "https://sub.example.com"
        );
    }

    #[test]
    fn query_free_cuts_at_the_first_marker() {
        assert_eq!(query_free("a?b#c"), "a");
        assert_eq!(query_free("a#b"), "a");
        assert_eq!(query_free("a"), "a");
    }

    #[test]
    fn in_text_redacts_a_url_inside_a_chain() {
        let chain = "error sending request for url (https://sub.example.com/list?token=abc): \
                     connection refused";
        assert_eq!(
            in_text(chain),
            "error sending request for url (https://sub.example.com/list): connection refused"
        );
    }

    #[test]
    fn in_text_handles_several_urls_and_userinfo() {
        let text = "redirected https://a.example/x?k=1 then https://u:p@b.example/y?k=2 done";
        assert_eq!(
            in_text(text),
            "redirected https://a.example/x then https://b.example/y done"
        );
    }

    #[test]
    fn in_text_leaves_text_without_urls_alone() {
        let text = "dns error: failed to lookup address information: Temporary failure";
        assert_eq!(in_text(text), text);
    }

    #[test]
    fn in_text_keeps_trailing_punctuation_outside_the_url() {
        assert_eq!(
            in_text("failed: https://example.com/a?k=1, retrying"),
            "failed: https://example.com/a, retrying"
        );
    }
}
