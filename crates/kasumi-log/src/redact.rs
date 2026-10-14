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
}
