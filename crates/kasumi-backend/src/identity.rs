//! The automatic HWID and the request a subscription fetch sends.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use happ_sub::MetaMap;
use happ_sub::device::{HAPP_PACKAGE, HAPP_SIGNERS, decode_user_key, ssaid};
use happ_sub::incy_request::{self, derive_hwid, usable_android_id};
use happ_sub::incy_signers::{INCY_PACKAGE, INCY_SIGNERS};
use kasumi_core::request_identity::{
    AutoHwid, DeviceFacts, HwidSource, IdentityInput, RequestClient, Resolved, resolve,
};

use crate::fs::read_text;
use crate::fsjson::write_text_atomic;
use crate::platform::Platform;
use kasumi_log::{Area, ks_warn};

/// The HWID sent when none is typed, most Happ-like first: the SSAID Android gave an
/// installed Happ, the one it would give Happ, an app-scoped machine id, a random id.
pub async fn auto_happ_hwid(platform: &dyn Platform, android_user: u32) -> AutoHwid {
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
            source: HwidSource::HappMachineId,
        };
    }
    AutoHwid {
        value: happ_device_id(platform).await,
        source: HwidSource::HappDeviceId,
    }
}

/// Incy's HWID when none is typed. Incy hashes its `android_id`, which on Android 8+
/// is the SSAID Android gives Incy (stored once installed, else computed from the
/// user's SSAID key), with the build values; without a usable one it hashes a random
/// seed. The id an installed Incy keeps sits in keystore-encrypted preferences.
pub async fn auto_incy_hwid(
    platform: &dyn Platform,
    android_user: u32,
    facts: &DeviceFacts,
) -> AutoHwid {
    let b = &facts.build;
    let device = |android_id| incy_request::DeviceFacts {
        android_id,
        manufacturer: &b.manufacturer,
        model: &facts.model,
        brand: &b.brand,
        device: &b.device,
        product: &b.product,
        board: &b.board,
        hardware: &b.hardware,
        ..Default::default()
    };
    let stored = platform
        .stored_ssaid(android_user, INCY_PACKAGE)
        .await
        .map(|s| s.trim().to_owned())
        .filter(|s| is_hex16(s));
    let android_id = match stored {
        Some(id) => Some(id),
        None => platform
            .ssaid_user_key(android_user)
            .await
            .and_then(|hex| decode_user_key(&hex).ok())
            .and_then(|key| ssaid(&key, &INCY_SIGNERS).ok()),
    };
    if let Some(id) = android_id.filter(|id| usable_android_id(id)) {
        return AutoHwid {
            value: derive_hwid(None, &device(Some(&id)), ""),
            source: HwidSource::IncyDerived,
        };
    }
    let seed = incy_seed(platform).await;
    AutoHwid {
        value: derive_hwid(Some(&seed), &device(None), &seed),
        source: HwidSource::IncySeed,
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
    let user = input.defaults.android_user;
    let auto = match input.client {
        RequestClient::Happ => auto_happ_hwid(platform, user).await,
        RequestClient::Incy => auto_incy_hwid(platform, user, &facts).await,
    };
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

/// A random id kept in `happ-device-id`, outside `app-state.json`, so restoring a backup on
/// another device does not clone it.
async fn happ_device_id(platform: &dyn Platform) -> String {
    static CREATE: Mutex<()> = Mutex::const_new(());
    let _g = CREATE.lock().await;
    let path = platform.paths().happ_device_id();
    if let Some(id) = read_text(&path)
        .await
        .map(|s| s.trim().to_owned())
        .filter(|s| is_hex16(s))
    {
        return id;
    }
    let id = hex(&Sha256::digest(uuid::Uuid::new_v4().as_bytes())[..8]);
    if let Err(e) = write_text_atomic(&path, &id).await {
        ks_warn!(Area::State, "writing {}: {e}", path.display());
    }
    id
}

/// Incy's random seed, a UUID without dashes, kept in `incy-seed` like `happ-device-id`.
async fn incy_seed(platform: &dyn Platform) -> String {
    static CREATE: Mutex<()> = Mutex::const_new(());
    let _g = CREATE.lock().await;
    let path = platform.paths().incy_seed();
    if let Some(seed) = read_text(&path)
        .await
        .map(|s| s.trim().to_owned())
        .filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return seed;
    }
    let seed = uuid::Uuid::new_v4().simple().to_string();
    if let Err(e) = write_text_atomic(&path, &seed).await {
        log::warn!("writing {}: {e}", path.display());
    }
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestPlatform;

    // Synthetic 32-byte key 00..1f; happ-sub pins its SSAID for Happ's signer.
    const KEY: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    const KEY_SSAID: &str = "013b86e99e8dce53";

    #[tokio::test]
    async fn happ_stored_ssaid_wins() {
        let (p, _d) = TestPlatform::new();
        p.identity(|i| {
            i.stored_ssaid = Some("00112233aabbccdd".into());
            i.user_key = Some(KEY.into());
            i.machine_id = Some("m".into());
        });
        let hwid = auto_happ_hwid(&p, 0).await;
        assert_eq!(hwid.value, "00112233aabbccdd");
        assert_eq!(hwid.source, HwidSource::HappStored);
        assert_eq!(p.identity_calls(), ["stored:0:su.happ.proxyutility"]);
    }

    #[tokio::test]
    async fn happ_computed_ssaid_when_not_installed() {
        let (p, _d) = TestPlatform::new();
        p.identity(|i| {
            i.stored_ssaid = Some("not an ssaid".into());
            i.user_key = Some(KEY.into());
        });
        let hwid = auto_happ_hwid(&p, 10).await;
        assert_eq!(hwid.value, KEY_SSAID);
        assert_eq!(hwid.source, HwidSource::HappComputed);
        assert_eq!(
            p.identity_calls(),
            ["stored:10:su.happ.proxyutility", "userkey:10"]
        );
    }

    #[tokio::test]
    async fn happ_machine_id_hashed_not_raw() {
        let (p, _d) = TestPlatform::new();
        let raw = "5f3c8a1e9b2d4c6f8e0a1b2c3d4e5f60";
        p.identity(|i| i.machine_id = Some(format!("{raw}\n")));
        let hwid = auto_happ_hwid(&p, 0).await;
        assert_eq!(hwid.source, HwidSource::HappMachineId);
        assert!(is_hex16(&hwid.value));
        assert!(!raw.contains(&hwid.value));
        assert_eq!(hwid.value, app_scoped(raw));
        assert_ne!(app_scoped(raw), app_scoped("another-host"));
    }

    #[tokio::test]
    async fn happ_persisted_random_is_stable_and_outside_app_state() {
        let (p, _d) = TestPlatform::new();
        let first = auto_happ_hwid(&p, 0).await;
        assert_eq!(first.source, HwidSource::HappDeviceId);
        assert!(is_hex16(&first.value));
        assert_eq!(auto_happ_hwid(&p, 0).await, first);
        let stored = std::fs::read_to_string(p.paths().happ_device_id()).unwrap();
        assert_eq!(stored, first.value);
        assert!(!p.paths().app_state.exists());

        let (other, _d2) = TestPlatform::new();
        assert_ne!(auto_happ_hwid(&other, 0).await.value, first.value);
    }

    fn phone() -> DeviceFacts {
        DeviceFacts {
            model: "Pixel 9".into(),
            build: kasumi_core::request_identity::AndroidBuild {
                manufacturer: "Google".into(),
                brand: "google".into(),
                device: "tokay".into(),
                product: "tokay".into(),
                board: "tokay".into(),
                hardware: "tokay".into(),
            },
            ..Default::default()
        }
    }

    /// Incy's id for `android_id` on [`phone`], spelled out from happ-sub's documented
    /// steps: the seed hashes the id with the build values, the id hashes the seed.
    fn incy_id(android_id: &str) -> String {
        let material = format!("{android_id}|Google|Pixel 9|google|tokay|tokay|tokay|tokay");
        let seed = hex(&Sha256::digest(material.as_bytes()));
        let digest = hex(&Sha256::digest(format!("incy_hwid_{seed}").as_bytes())).to_uppercase();
        format!(
            "{}-{}-{}-{}-{}",
            &digest[..8],
            &digest[8..12],
            &digest[12..16],
            &digest[16..20],
            &digest[20..32]
        )
    }

    #[tokio::test]
    async fn incy_hashes_the_ssaid_android_gave_incy() {
        let (p, _d) = TestPlatform::new();
        p.identity(|i| {
            i.stored_ssaid = Some("00112233aabbccdd".into());
            i.user_key = Some(KEY.into());
        });
        let hwid = auto_incy_hwid(&p, 0, &phone()).await;
        assert_eq!(hwid.value, incy_id("00112233aabbccdd"));
        assert_eq!(hwid.source, HwidSource::IncyDerived);
        assert_eq!(p.identity_calls(), ["stored:0:llc.itdev.incy"]);
    }

    #[tokio::test]
    async fn incy_computes_its_ssaid_when_not_installed() {
        let (p, _d) = TestPlatform::new();
        p.identity(|i| i.user_key = Some(KEY.into()));
        let hwid = auto_incy_hwid(&p, 10, &phone()).await;
        let ssaid = ssaid(&decode_user_key(KEY).unwrap(), &INCY_SIGNERS).unwrap();
        assert_ne!(ssaid, KEY_SSAID, "Incy's signer gives its own SSAID");
        assert_eq!(hwid.value, incy_id(&ssaid));
        assert_eq!(hwid.source, HwidSource::IncyDerived);
        assert_eq!(
            p.identity_calls(),
            ["stored:10:llc.itdev.incy", "userkey:10"]
        );
    }

    #[tokio::test]
    async fn incy_falls_back_to_a_kept_random_seed() {
        let (p, _d) = TestPlatform::new();
        p.identity(|i| i.machine_id = Some("m".into()));
        let first = auto_incy_hwid(&p, 0, &phone()).await;
        assert_eq!(first.source, HwidSource::IncySeed);
        assert_eq!(first.value.len(), 36);
        assert_eq!(auto_incy_hwid(&p, 0, &phone()).await, first);
        let seed = std::fs::read_to_string(p.paths().incy_seed()).unwrap();
        assert_eq!(seed.len(), 32);
        assert_eq!(
            first.value,
            derive_hwid(Some(&seed), &Default::default(), "")
        );
    }
}
