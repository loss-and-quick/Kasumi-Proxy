//! The automatic HWID and the request a subscription fetch sends.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use happ_sub::MetaMap;
use happ_sub::device::{HAPP_PACKAGE, HAPP_SIGNERS, decode_user_key, ssaid};
use kasumi_core::request_identity::{AutoHwid, HwidSource, IdentityInput, Resolved, resolve};

use crate::fs::read_text;
use crate::fsjson::write_text_atomic;
use crate::platform::Platform;

/// The HWID sent when none is typed, most Happ-like first: the SSAID Android gave an
/// installed Happ, the one it would give Happ, an app-scoped machine id, a random id.
pub async fn auto_hwid(platform: &dyn Platform, android_user: u32) -> AutoHwid {
    let valid = |s: String| Some(s.trim().to_owned()).filter(|s| is_hex16(s));
    if let Some(value) = platform
        .stored_ssaid(android_user, HAPP_PACKAGE)
        .await
        .and_then(valid)
    {
        return AutoHwid {
            value,
            source: HwidSource::HappStored,
        };
    }
    let computed = platform
        .ssaid_user_key(android_user)
        .await
        .and_then(|hex| decode_user_key(&hex).ok())
        .and_then(|key| ssaid(&key, &HAPP_SIGNERS).ok());
    if let Some(value) = computed {
        return AutoHwid {
            value,
            source: HwidSource::HappComputed,
        };
    }
    if let Some(id) = platform
        .machine_id()
        .await
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
    {
        return AutoHwid {
            value: app_scoped(&id),
            source: HwidSource::MachineId,
        };
    }
    AutoHwid {
        value: device_id(platform).await,
        source: HwidSource::DeviceId,
    }
}

/// The request a fetch with `input` sends, given the subscription's stored provider meta.
pub async fn resolve_request(
    platform: &dyn Platform,
    input: &IdentityInput,
    meta: Option<&MetaMap>,
    consented: &[String],
) -> Resolved {
    let facts = platform.device_facts().await;
    let auto = auto_hwid(platform, input.defaults.android_user).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    resolve(input, &facts, &auto, meta, consented, now)
}

fn is_hex16(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// machine-id(5) asks applications not to expose the raw id, so send a keyed hash.
fn app_scoped(machine_id: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(b"kasumi-proxy/hwid").expect("HMAC accepts any key length");
    mac.update(machine_id.as_bytes());
    hex(&mac.finalize().into_bytes()[..8])
}

/// A random id kept in `device-id`, outside `app-state.json`, so restoring a backup on
/// another device does not clone it.
async fn device_id(platform: &dyn Platform) -> String {
    static CREATE: Mutex<()> = Mutex::const_new(());
    let _g = CREATE.lock().await;
    let path = platform.paths().device_id();
    if let Some(id) = read_text(&path)
        .await
        .map(|s| s.trim().to_owned())
        .filter(|s| is_hex16(s))
    {
        return id;
    }
    let id = hex(&Sha256::digest(uuid::Uuid::new_v4().as_bytes())[..8]);
    if let Err(e) = write_text_atomic(&path, &id).await {
        log::warn!("writing {}: {e}", path.display());
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestPlatform;

    // Synthetic 32-byte key 00..1f; happ-sub pins its SSAID for Happ's signer.
    const KEY: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    const KEY_SSAID: &str = "013b86e99e8dce53";

    #[tokio::test]
    async fn stored_ssaid_wins() {
        let (p, _d) = TestPlatform::new();
        p.identity(|i| {
            i.stored_ssaid = Some("00112233aabbccdd".into());
            i.user_key = Some(KEY.into());
            i.machine_id = Some("m".into());
        });
        let hwid = auto_hwid(&p, 0).await;
        assert_eq!(hwid.value, "00112233aabbccdd");
        assert_eq!(hwid.source, HwidSource::HappStored);
        assert_eq!(p.identity_calls(), ["stored:0:su.happ.proxyutility"]);
    }

    #[tokio::test]
    async fn computed_ssaid_when_not_installed() {
        let (p, _d) = TestPlatform::new();
        p.identity(|i| {
            i.stored_ssaid = Some("not an ssaid".into());
            i.user_key = Some(KEY.into());
        });
        let hwid = auto_hwid(&p, 10).await;
        assert_eq!(hwid.value, KEY_SSAID);
        assert_eq!(hwid.source, HwidSource::HappComputed);
        assert_eq!(
            p.identity_calls(),
            ["stored:10:su.happ.proxyutility", "userkey:10"]
        );
    }

    #[tokio::test]
    async fn machine_id_hashed_not_raw() {
        let (p, _d) = TestPlatform::new();
        let raw = "5f3c8a1e9b2d4c6f8e0a1b2c3d4e5f60";
        p.identity(|i| i.machine_id = Some(format!("{raw}\n")));
        let hwid = auto_hwid(&p, 0).await;
        assert_eq!(hwid.source, HwidSource::MachineId);
        assert!(is_hex16(&hwid.value));
        assert!(!raw.contains(&hwid.value));
        assert_eq!(hwid.value, app_scoped(raw));
        assert_ne!(app_scoped(raw), app_scoped("another-host"));
    }

    #[tokio::test]
    async fn persisted_random_is_stable_and_outside_app_state() {
        let (p, _d) = TestPlatform::new();
        let first = auto_hwid(&p, 0).await;
        assert_eq!(first.source, HwidSource::DeviceId);
        assert!(is_hex16(&first.value));
        assert_eq!(auto_hwid(&p, 0).await, first);
        let stored = std::fs::read_to_string(p.paths().device_id()).unwrap();
        assert_eq!(stored, first.value);
        assert!(!p.paths().app_state.exists());

        let (other, _d2) = TestPlatform::new();
        assert_ne!(auto_hwid(&other, 0).await.value, first.value);
    }
}
