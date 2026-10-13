//! The cookie jar subscription fetches share. Like Happ's, it lives in memory only
//! and is gone after a restart; unlike an unbounded jar, a provider cannot grow it
//! for as long as the process runs.
//!
//! cookie_store has no per-host limit, so the cap is global: a host that sets many
//! cookies pushes out the oldest cookies of every host.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use cookie_store::{Cookie, CookieStore, RawCookie, StoreAction};
use reqwest::Url;
use reqwest::header::HeaderValue;

/// Most cookies kept; past it the oldest go first.
const MAX_COOKIES: usize = 300;
/// A cookie whose name and value together are larger is dropped, as browsers do
/// (RFC 6265 asks a client to store at least 4096 bytes per cookie).
const MAX_COOKIE_BYTES: usize = 4096;

/// Domain, path and name: what identifies a cookie in the store.
type Key = (String, String, String);

#[derive(Default)]
pub struct SubCookies(Mutex<Jar>);

#[derive(Default)]
struct Jar {
    store: CookieStore,
    /// When each stored cookie was first set, as a sequence number.
    created: HashMap<Key, u64>,
    next: u64,
}

impl SubCookies {
    fn jar(&self) -> MutexGuard<'_, Jar> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Jar {
    fn insert(&mut self, raw: &RawCookie<'_>, url: &Url) {
        if raw.name().len() + raw.value().len() > MAX_COOKIE_BYTES {
            return;
        }
        let Ok(cookie) = Cookie::try_from_raw_cookie(raw, url) else {
            return;
        };
        let key = key(&cookie);
        match self.store.insert(cookie.into_owned(), url) {
            // A replaced cookie keeps its creation time (RFC 6265 5.3, step 11).
            Ok(StoreAction::Inserted | StoreAction::UpdatedExisting) => {
                self.created.entry(key).or_insert(self.next);
                self.next += 1;
            }
            // cookie_store would keep it, only marked expired.
            Ok(StoreAction::ExpiredExisting) => self.remove(&key),
            Err(_) => {}
        }
        while self.created.len() > MAX_COOKIES {
            let Some(oldest) = self
                .created
                .iter()
                .min_by_key(|(_, seq)| **seq)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.remove(&oldest);
        }
    }

    fn remove_expired(&mut self) {
        let expired: Vec<Key> = self
            .store
            .iter_any()
            .filter(|c| c.is_expired())
            .map(key)
            .collect();
        for key in &expired {
            self.remove(key);
        }
    }

    fn remove(&mut self, key: &Key) {
        let (domain, path, name) = key;
        self.store.remove(domain, path, name);
        self.created.remove(key);
    }
}

fn key(c: &Cookie<'_>) -> Key {
    (
        String::from(&c.domain),
        String::from(&c.path),
        c.name().to_owned(),
    )
}

/// Counts the cookies and leaves them out: they are credentials.
impl std::fmt::Debug for SubCookies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubCookies")
            .field("len", &self.jar().created.len())
            .finish()
    }
}

impl reqwest::cookie::CookieStore for SubCookies {
    fn set_cookies(&self, cookie_headers: &mut dyn Iterator<Item = &HeaderValue>, url: &Url) {
        let mut jar = self.jar();
        jar.remove_expired();
        for value in cookie_headers {
            let Ok(text) = value.to_str() else {
                continue;
            };
            if let Ok(raw) = RawCookie::parse(text) {
                jar.insert(&raw, url);
            }
        }
    }

    fn cookies(&self, url: &Url) -> Option<HeaderValue> {
        let jar = self.jar();
        let header = jar
            .store
            .get_request_values(url)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ");
        if header.is_empty() {
            return None;
        }
        HeaderValue::from_str(&header).ok()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use kasumi_core::contract::FetchMode;
    use reqwest::cookie::CookieStore as _;

    use super::*;
    use crate::net::{FetchUrlOptions, fetch};
    use crate::testutil::{http_response, serve};

    fn url() -> Url {
        "https://sub.example.org/s".parse().unwrap()
    }

    fn set(jar: &SubCookies, headers: &[String]) {
        let values: Vec<HeaderValue> = headers
            .iter()
            .map(|h| HeaderValue::from_str(h).unwrap())
            .collect();
        jar.set_cookies(&mut values.iter(), &url());
    }

    fn sent(jar: &SubCookies) -> Vec<String> {
        jar.cookies(&url())
            .map(|v| v.to_str().unwrap().split("; ").map(str::to_owned).collect())
            .unwrap_or_default()
    }

    /// Cookies held, expired ones included.
    fn held(jar: &SubCookies) -> usize {
        let jar = jar.jar();
        assert_eq!(jar.store.iter_any().count(), jar.created.len());
        jar.created.len()
    }

    #[test]
    fn holds_at_most_the_cap_dropping_the_oldest() {
        let jar = SubCookies::default();
        let headers: Vec<String> = (0..MAX_COOKIES + 100)
            .map(|i| format!("c{i}=1; Path=/"))
            .collect();
        set(&jar, &headers[..150]);
        set(&jar, &headers[150..]);
        assert_eq!(held(&jar), MAX_COOKIES);
        let mut kept = sent(&jar);
        kept.sort();
        let mut newest: Vec<String> = (100..MAX_COOKIES + 100)
            .map(|i| format!("c{i}=1"))
            .collect();
        newest.sort();
        assert_eq!(kept, newest);
    }

    #[test]
    fn a_replaced_cookie_keeps_its_age() {
        let jar = SubCookies::default();
        let mut headers: Vec<String> = (0..MAX_COOKIES)
            .map(|i| format!("c{i}=1; Path=/"))
            .collect();
        set(&jar, &headers);
        headers = vec!["c0=2; Path=/".into(), "new=1; Path=/".into()];
        set(&jar, &headers);
        let kept = sent(&jar);
        assert_eq!(kept.len(), MAX_COOKIES);
        assert!(!kept.iter().any(|c| c.starts_with("c0=")), "{kept:?}");
        assert!(kept.contains(&"new=1".to_owned()));
    }

    #[test]
    fn an_oversized_cookie_is_dropped() {
        let jar = SubCookies::default();
        let fits = format!("fits={}; Path=/", "x".repeat(MAX_COOKIE_BYTES - 4));
        let big = format!("big={}; Path=/", "x".repeat(MAX_COOKIE_BYTES - 2));
        set(&jar, &[fits, big, "small=1; Path=/".into()]);
        assert_eq!(held(&jar), 2);
        let kept = sent(&jar);
        assert!(kept.iter().any(|c| c.starts_with("fits=")));
        assert!(kept.contains(&"small=1".to_owned()));
        assert!(!kept.iter().any(|c| c.starts_with("big=")));
    }

    #[tokio::test]
    async fn expired_cookies_are_evicted() {
        let jar = SubCookies::default();
        set(
            &jar,
            &["soon=1; Path=/; Max-Age=1".into(), "gone=1; Path=/".into()],
        );
        set(&jar, &["gone=; Path=/; Max-Age=0".into()]);
        assert_eq!(held(&jar), 1, "the server's expiry removes it");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        set(&jar, &["new=1; Path=/".into()]);
        assert_eq!(
            held(&jar),
            1,
            "a lapsed cookie is removed on the next insert"
        );
        assert_eq!(sent(&jar), ["new=1"]);
    }

    #[test]
    fn debug_leaves_values_out() {
        let jar = SubCookies::default();
        set(&jar, &["id=secret-value; Path=/".into()]);
        let shown = format!("{jar:?}");
        assert!(!shown.contains("secret-value"), "{shown}");
    }

    #[tokio::test]
    async fn cookies_round_trip_within_a_run() {
        let (base, requests) = serve(vec![
            http_response(200, &[("set-cookie", "id=abc; Path=/")], b"ok"),
            http_response(200, &[], b"ok"),
        ])
        .await;
        let opts = FetchUrlOptions {
            mode: FetchMode::Direct,
            timeout: Some(Duration::from_secs(5)),
            cookie_jar: Some(Arc::new(SubCookies::default())),
            ..FetchUrlOptions::default()
        };
        fetch(&format!("{base}/a"), opts.clone()).await.unwrap();
        fetch(&format!("{base}/b"), opts).await.unwrap();
        let requests = requests.lock().unwrap();
        let cookie = |i: usize| {
            requests[i]
                .lines()
                .filter_map(|l| l.split_once(": "))
                .find(|(n, _)| n.eq_ignore_ascii_case("cookie"))
                .map(|(_, v)| v.to_owned())
        };
        assert_eq!(cookie(0), None);
        assert_eq!(cookie(1).as_deref(), Some("id=abc"));
    }
}
