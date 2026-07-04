//! The typed command surface both transports share. A [`Command`] carries its
//! inputs as typed fields (no stringly `args`/`payload`); [`dispatch`] runs one
//! against a [`Platform`] and returns a typed [`Response`]. The desktop Tauri layer
//! and the Android daemon's WS both serialize this exact pair, so there is a single
//! command set and no duplication between them.
//!
//! Stateless commands resolve here directly. Lifecycle (`start`/`stop`/`restart`/
//! `reloadAppFilter`) and the on-demand diagnostics (`ping`/`speedTest`) are owned
//! by higher layers (the `Service` and the jobs module) and join this enum in their
//! own slices; nothing here proxies them over a socket.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use kasumi_core::contract::{Capabilities, FetchMode, LogTarget, ServiceState, TestKind, WsInfo};
use kasumi_core::core_config::{CoreConfig, build_core_config};
use kasumi_core::mutate::{MutationIntent, apply_mutation};
use kasumi_core::profile::Profile;
use kasumi_core::share::{build_share_link, parse_share_links};
use kasumi_core::state::{AppState, DEFAULT_LOG_ROTATE_KB, default_app_state};

use crate::fs::{read_text, write_text};
use crate::fsjson::{read_json, write_bytes_atomic};
use crate::net::{FetchUrlOptions, fetch_url, used_ports};
use crate::platform::{AppInfo, Platform};

/// First port `freePorts` probes when the caller doesn't pin a start.
const FREE_PORTS_BASE: u16 = kasumi_core::contract::TEST_PORT_BASE;
/// Default tail length for `log`.
const LOG_TAIL_LINES: usize = 200;

/// Bad input or a failed operation; transports map it to their error form.
#[derive(Debug, Clone)]
pub struct CommandError(pub String);

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CommandError {}

fn err(msg: impl Into<String>) -> CommandError {
    CommandError(msg.into())
}

/// One client request. The tag `cmd` selects the variant; fields are its inputs.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(tag = "cmd", rename_all = "camelCase")]
pub enum Command {
    ReadState,
    /// The single write path: apply one domain intent to the persisted state. The
    /// handler reads the current state, applies the intent (pure
    /// `kasumi_core::mutate`), runs the write-side middleware chain, persists, and
    /// returns the new canonical `AppState`. Routed through the `Service` so it runs
    /// under the state-write lock; the stateless `dispatch` rejects it.
    Mutate {
        intent: Box<MutationIntent>,
    },
    #[serde(rename_all = "camelCase")]
    FetchSubscription {
        url: String,
        #[serde(default)]
        mode: FetchMode,
        #[serde(default)]
        user_agent: Option<String>,
        #[serde(default)]
        allow_insecure: bool,
    },
    DownloadAsset {
        filename: String,
        url: String,
        #[serde(default)]
        mode: FetchMode,
    },
    FreePorts {
        #[serde(default)]
        start: Option<u16>,
        #[serde(default)]
        count: Option<u32>,
        #[serde(default)]
        span: Option<u16>,
    },
    ListAssets,
    Capabilities,
    ListApps,
    Log {
        #[serde(default)]
        target: Option<LogTarget>,
        #[serde(default)]
        lines: Option<u32>,
    },
    ClearLogs,
    RotateLogs {
        #[serde(default, rename = "maxKb")]
        max_kb: Option<u32>,
    },
    Status,
    WsInfo,
    #[serde(rename_all = "camelCase")]
    DumpConfig {
        profile_id: String,
    },
    #[serde(rename_all = "camelCase")]
    TestLog {
        profile_id: String,
        kind: TestKind,
    },
    #[serde(rename_all = "camelCase")]
    ParseShareLinks {
        text: String,
        #[serde(default)]
        group_id: Option<String>,
    },
    BuildShareLink {
        profile: Box<Profile>,
    },
    #[serde(rename_all = "camelCase")]
    Ping {
        profile_id: String,
    },
    // No port: the daemon leases its own per test and bounds concurrency itself, so
    // a caller just fires one of these per profile (solo or batch — batch is simply
    // many of them) and can keep adding more while others run.
    #[serde(rename_all = "camelCase")]
    RealPing {
        profile_id: String,
    },
    #[serde(rename_all = "camelCase")]
    SpeedTest {
        profile_id: String,
    },
    // Lifecycle: stateful, owned by the Service's serialized chain. The stateless
    // `dispatch` rejects them; `Service::dispatch` intercepts and runs them.
    #[serde(rename_all = "camelCase")]
    Start {
        #[serde(default)]
        profile_id: Option<String>,
    },
    Stop,
    #[serde(rename_all = "camelCase")]
    Restart {
        #[serde(default)]
        profile_id: Option<String>,
    },
    ReloadAppFilter,
    // Fetch one subscription and apply it server-side (the same path the headless
    // updater uses), persisting and restarting the active data-path when affected.
    // Needs the Service's serializer + lifecycle, so the stateless `dispatch` rejects
    // it and `Service::dispatch` runs it. Returns the new merged `AppState`.
    #[serde(rename_all = "camelCase")]
    ApplySubscription {
        sub_id: String,
    },
}

/// One reply. The tag `kind` selects the payload shape under `value`.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
pub enum Response {
    State(Box<AppState>),
    Profiles(Vec<Profile>),
    Text(String),
    Ports(Vec<u16>),
    Assets(Vec<String>),
    Capabilities(Capabilities),
    Apps(Vec<AppInfo>),
    Status(ServiceState),
    WsInfo(Option<WsInfo>),
    /// Latency in ms (tcp-ping and real-ping); `null` when there is no result.
    Ping(Option<i64>),
    /// Throughput in bytes/sec; `null` when there is no result.
    Speed(Option<i64>),
    /// A bare acknowledgement (`{ok: true}` / no body in the old protocol).
    Ok,
}

/// Reject path traversal / quoting tricks in asset filenames.
fn safe_filename(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains("..")
        && !name.contains('"')
        && !name.contains('\\')
}

/// Names of files in `dir` ending in `suffix`, alphabetically. Missing dir → empty.
async fn list_dir(dir: &Path, suffix: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(entry)) = rd.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(suffix) {
                out.push(name);
            }
        }
    }
    out.sort();
    out
}

/// Resolve a profile by id and build its launch config, then let the platform apply
/// any OS-specific tweaks. The server-side replacement for the UI building config.
pub(crate) async fn build_profile_config(
    platform: &dyn Platform,
    id: &str,
) -> Result<CoreConfig, CommandError> {
    let paths = platform.paths();
    let state: AppState = read_json(&paths.app_state)
        .await
        .ok_or_else(|| err("app-state not found"))?;
    let profiles: Vec<Profile> = read_json(&paths.profiles).await.unwrap_or_default();
    let profile = profiles
        .iter()
        .find(|p| p.meta().id == id)
        .ok_or_else(|| err(format!("profile not found: {id}")))?;
    let srs_dir = paths.srs_dir.to_str().unwrap_or("");
    let mut built = build_core_config(
        profile,
        &state.settings,
        &state.routing_rules,
        &profiles,
        srs_dir,
    )
    .map_err(err)?;
    platform.tune_config(built.engine, &mut built.config);
    Ok(built)
}

/// Run one command against `platform`, returning its typed reply.
pub async fn dispatch(platform: &dyn Platform, cmd: Command) -> Result<Response, CommandError> {
    let paths = platform.paths();
    match cmd {
        Command::ReadState => {
            // The single read path: the full canonical state — profiles merged in,
            // schema-migrated and normalized — so the UI renders it as-is (no
            // client-side merge/normalize, mirroring the single Mutate write path).
            let state = crate::state::read_app_state(platform)
                .await
                .unwrap_or_else(default_app_state);
            Ok(Response::State(Box::new(state)))
        }
        Command::FetchSubscription {
            url,
            mode,
            user_agent,
            allow_insecure,
        } => {
            let url = url.trim();
            if url.is_empty() {
                return Err(err("empty subscription URL"));
            }
            let proxy = platform
                .proxy_status()
                .await
                .map_err(|e| err(e.to_string()))?;
            let body = fetch_url(
                url,
                FetchUrlOptions {
                    mode,
                    proxy: Some(proxy),
                    user_agent,
                    allow_insecure,
                    timeout: None,
                },
            )
            .await
            .map_err(|e| err(e.to_string()))?;
            Ok(Response::Text(String::from_utf8_lossy(&body).into_owned()))
        }

        Command::DownloadAsset {
            filename,
            url,
            mode,
        } => {
            if !safe_filename(&filename) {
                return Err(err("invalid filename"));
            }
            let url = url.trim();
            if url.is_empty() {
                return Err(err("empty asset URL"));
            }
            let proxy = platform
                .proxy_status()
                .await
                .map_err(|e| err(e.to_string()))?;
            let body = fetch_url(
                url,
                FetchUrlOptions {
                    mode,
                    proxy: Some(proxy),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| err(e.to_string()))?;
            if body.is_empty() {
                return Err(err("download failed"));
            }
            write_bytes_atomic(paths.dat_dir.join(&filename), &body)
                .await
                .map_err(|e| err(e.to_string()))?;
            platform
                .convert_asset(&filename)
                .await
                .map_err(|e| err(e.to_string()))?;
            Ok(Response::Ok)
        }

        Command::FreePorts { start, count, span } => {
            let start = start.unwrap_or(FREE_PORTS_BASE) as u32;
            let count = count.unwrap_or(1);
            let span = span.unwrap_or(1) as u32;
            let used = used_ports().await;
            let mut ports = Vec::new();
            let mut port = start;
            while (ports.len() as u32) < count && port <= 65000 {
                if (0..span).all(|i| !used.contains(&((port + i) as u16))) {
                    ports.push(port as u16);
                    port += span;
                } else {
                    port += 1;
                }
            }
            Ok(Response::Ports(ports))
        }

        Command::ListAssets => Ok(Response::Assets(list_dir(&paths.dat_dir, ".dat").await)),

        Command::Capabilities => {
            let c = platform
                .capabilities()
                .await
                .map_err(|e| err(e.to_string()))?;
            Ok(Response::Capabilities(Capabilities {
                bridge: c.bridge,
                xray_version: c.cores.xray.unwrap_or_default(),
                singbox_version: c.cores.singbox.unwrap_or_default(),
                tun: c.tun,
            }))
        }

        Command::ListApps => {
            let apps = match platform.app_filter() {
                Some(f) => f.list_apps().await.map_err(|e| err(e.to_string()))?,
                None => Vec::new(),
            };
            Ok(Response::Apps(apps))
        }

        Command::Log { target, lines } => {
            let target = target.unwrap_or(LogTarget::Daemon);
            let lines = lines.map(|n| n as usize).unwrap_or(LOG_TAIL_LINES);
            let path = paths.log(target);
            let Some(txt) = read_text(&path).await else {
                return Ok(Response::Text(format!("(no log: {})", path.display())));
            };
            if txt.is_empty() {
                return Ok(Response::Text(format!("(empty log: {})", path.display())));
            }
            let body = txt.strip_suffix('\n').unwrap_or(&txt);
            let all: Vec<&str> = body.split('\n').collect();
            let from = all.len().saturating_sub(lines);
            Ok(Response::Text(all[from..].join("\n")))
        }

        Command::ClearLogs => {
            for target in LOG_TARGETS {
                let _ = write_text(paths.log(target), "").await;
            }
            Ok(Response::Ok)
        }

        Command::RotateLogs { max_kb } => {
            let default_kb = read_json::<AppState>(&paths.app_state)
                .await
                .map(|s| s.settings.log_rotate_max_kb)
                .unwrap_or(DEFAULT_LOG_ROTATE_KB);
            let kb = max_kb
                .map(i64::from)
                .filter(|&v| v > 0)
                .unwrap_or(default_kb);
            let limit = kb.max(0) as usize * 1024;
            for target in LOG_TARGETS {
                let path = paths.log(target);
                if let Some(txt) = read_text(&path).await
                    && txt.len() > limit
                {
                    // Keep roughly the second half, cut on a char boundary.
                    let mut start = txt.len() - limit / 2;
                    while start < txt.len() && !txt.is_char_boundary(start) {
                        start += 1;
                    }
                    let _ = crate::fsjson::write_text_atomic(&path, &txt[start..]).await;
                }
            }
            Ok(Response::Ok)
        }

        Command::Status => Ok(Response::Status(
            platform
                .service_state()
                .await
                .map_err(|e| err(e.to_string()))?,
        )),

        Command::WsInfo => Ok(Response::WsInfo(read_json(&paths.ws_info).await)),

        Command::DumpConfig { profile_id } => {
            let built = build_profile_config(platform, &profile_id).await?;
            let text =
                serde_json::to_string_pretty(&built.config).map_err(|e| err(e.to_string()))?;
            Ok(Response::Text(text))
        }

        Command::TestLog { profile_id, kind } => Ok(Response::Text(
            crate::jobs::read_test_log(platform, &profile_id, kind).await,
        )),

        Command::ParseShareLinks { text, group_id } => Ok(Response::Profiles(parse_share_links(
            &text,
            group_id.as_deref(),
        ))),

        Command::BuildShareLink { profile } => Ok(Response::Text(build_share_link(&profile))),

        Command::Ping { profile_id } => Ok(Response::Ping(
            crate::jobs::run_ping(platform, &profile_id).await,
        )),
        // A test-core start failure surfaces as a WS error (ok:false); `Ok(None)`
        // still means "core ran, server unreachable" — a normal no-result.
        Command::RealPing { profile_id } => crate::jobs::run_real_ping(platform, &profile_id)
            .await
            .map(Response::Ping)
            .map_err(err),
        Command::SpeedTest { profile_id } => crate::jobs::run_speed_test(platform, &profile_id)
            .await
            .map(Response::Speed)
            .map_err(err),

        Command::Mutate { .. }
        | Command::Start { .. }
        | Command::Stop
        | Command::Restart { .. }
        | Command::ReloadAppFilter
        | Command::ApplySubscription { .. } => Err(err(
            "stateful commands must be dispatched through the Service",
        )),
    }
}

/// Apply one [`MutationIntent`] to the persisted state and return the new canonical
/// `AppState`. Read current → apply intent (pure) → run the write-side middleware
/// chain (invariants) → persist. The caller (`Service`) holds the state-write lock so
/// concurrent mutations don't lose each other's update.
pub(crate) async fn run_mutation(
    platform: &dyn Platform,
    intent: &MutationIntent,
) -> Result<AppState, CommandError> {
    let prev = crate::state::read_app_state(platform)
        .await
        .unwrap_or_else(default_app_state);
    let mut next = prev.clone();
    apply_mutation(&mut next, intent);
    persist_with_chain(platform, &prev, &mut next)
        .await
        .map_err(|e| err(e.to_string()))?;
    let kept: std::collections::HashSet<&str> =
        next.profiles.iter().map(|p| p.meta().id.as_str()).collect();
    for p in &prev.profiles {
        if !kept.contains(p.meta().id.as_str()) {
            crate::jobs::remove_test_logs(platform, &p.meta().id).await;
        }
    }
    Ok(next)
}

/// Run the write-side middleware chain over `prev` → `next`, then persist `next`.
/// The single tail every persisted state change shares — the intent path
/// ([`run_mutation`]) and the subscription fetch path ([`crate::sub_update`]) — so
/// the chain is the one place invariants are enforced, on every write.
pub(crate) async fn persist_with_chain(
    platform: &dyn Platform,
    prev: &AppState,
    next: &mut AppState,
) -> std::io::Result<()> {
    crate::state_mw::default_chain().run(prev, next);
    crate::state::write_app_state(platform, next).await
}

const LOG_TARGETS: [LogTarget; 4] = [
    LogTarget::Daemon,
    LogTarget::Xray,
    LogTarget::Singbox,
    LogTarget::TunEngine,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsjson::write_json_atomic;
    use crate::testutil::{TestPlatform, sample_vless as vless};
    use kasumi_core::contract::RunState;

    #[tokio::test]
    async fn read_state_defaults_when_missing() {
        let (p, _d) = TestPlatform::new();
        let r = dispatch(&p, Command::ReadState).await.unwrap();
        let Response::State(state) = r else {
            panic!("expected state")
        };
        assert!(state.active_id.is_none());
        assert!(state.groups.iter().any(|g| g.id == "g-main"));
    }

    #[tokio::test]
    async fn mutate_applies_intent_persists_and_returns_canonical() {
        let (p, _d) = TestPlatform::new();
        // Seed a profile via an AddProfiles intent...
        let prof = vless();
        let id = prof.meta().id.clone();
        let next = run_mutation(
            &p,
            &MutationIntent::AddProfiles {
                profiles: vec![prof],
            },
        )
        .await
        .unwrap();
        assert_eq!(next.profiles.len(), 1);

        // ...set it active, then remove it: the chain must null the now-dangling
        // active_id, and the persisted state must reflect both writes (no split).
        run_mutation(
            &p,
            &MutationIntent::SetActive {
                id: Some(id.clone()),
            },
        )
        .await
        .unwrap();
        let after = run_mutation(&p, &MutationIntent::RemoveProfiles { ids: vec![id] })
            .await
            .unwrap();
        assert!(after.profiles.is_empty());
        assert_eq!(after.active_id, None);

        // One Mutate writes both files; ReadState merges them back into one canonical
        // state with profiles included.
        let Response::State(state) = dispatch(&p, Command::ReadState).await.unwrap() else {
            panic!()
        };
        assert_eq!(state.active_id, None);
        assert!(state.profiles.is_empty());
    }

    #[tokio::test]
    async fn mutate_is_rejected_on_stateless_path() {
        let (p, _d) = TestPlatform::new();
        let e = dispatch(
            &p,
            Command::Mutate {
                intent: Box::new(MutationIntent::SetActive { id: None }),
            },
        )
        .await
        .unwrap_err();
        assert!(e.0.contains("must be dispatched through the Service"));
    }

    #[tokio::test]
    async fn free_ports_returns_count_ascending_and_skips_used() {
        let (p, _d) = TestPlatform::new();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let taken = listener.local_addr().unwrap().port();
        let r = dispatch(
            &p,
            Command::FreePorts {
                start: Some(taken),
                count: Some(2),
                span: Some(1),
            },
        )
        .await
        .unwrap();
        let Response::Ports(ports) = r else { panic!() };
        assert_eq!(ports.len(), 2);
        assert!(!ports.contains(&taken));
        assert!(ports[0] < ports[1]);
    }

    #[tokio::test]
    async fn list_assets_sorted() {
        let (p, _d) = TestPlatform::new();
        std::fs::write(p.paths().dat_dir.join("geosite.dat"), b"x").unwrap();
        std::fs::write(p.paths().dat_dir.join("geoip.dat"), b"y").unwrap();
        std::fs::write(p.paths().dat_dir.join("notes.txt"), b"z").unwrap();
        let Response::Assets(a) = dispatch(&p, Command::ListAssets).await.unwrap() else {
            panic!()
        };
        assert_eq!(a, vec!["geoip.dat", "geosite.dat"]);
    }

    #[tokio::test]
    async fn capabilities_shaped_from_platform() {
        let (p, _d) = TestPlatform::new();
        let Response::Capabilities(c) = dispatch(&p, Command::Capabilities).await.unwrap() else {
            panic!()
        };
        assert_eq!(c.xray_version, "Xray 25.5.16");
        assert_eq!(c.singbox_version, "1.10.0");
        assert_eq!(c.bridge, "test");
        assert!(c.tun);
    }

    #[tokio::test]
    async fn log_missing_then_tail() {
        let (p, _d) = TestPlatform::new();
        let Response::Text(t) = dispatch(
            &p,
            Command::Log {
                target: Some(LogTarget::Xray),
                lines: None,
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert!(t.starts_with("(no log:"));

        write_text(p.paths().log(LogTarget::Xray), "a\nb\nc\nd\n")
            .await
            .unwrap();
        let Response::Text(t) = dispatch(
            &p,
            Command::Log {
                target: Some(LogTarget::Xray),
                lines: Some(2),
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert_eq!(t, "c\nd");
    }

    #[tokio::test]
    async fn clear_and_rotate_logs_ack() {
        let (p, _d) = TestPlatform::new();
        write_text(p.paths().log(LogTarget::Daemon), "noise")
            .await
            .unwrap();
        assert!(matches!(
            dispatch(&p, Command::ClearLogs).await.unwrap(),
            Response::Ok
        ));
        assert_eq!(
            read_text(p.paths().log(LogTarget::Daemon)).await.as_deref(),
            Some("")
        );
        assert!(matches!(
            dispatch(&p, Command::RotateLogs { max_kb: Some(1) })
                .await
                .unwrap(),
            Response::Ok
        ));
    }

    #[tokio::test]
    async fn status_reports_platform_state() {
        let (p, _d) = TestPlatform::new();
        let Response::Status(s) = dispatch(&p, Command::Status).await.unwrap() else {
            panic!()
        };
        assert_eq!(s.state, RunState::Connecting);
        assert_eq!(s.upload_bytes, 1);
    }

    #[tokio::test]
    async fn ws_info_none_when_missing() {
        let (p, _d) = TestPlatform::new();
        let Response::WsInfo(info) = dispatch(&p, Command::WsInfo).await.unwrap() else {
            panic!()
        };
        assert!(info.is_none());
    }

    #[tokio::test]
    async fn dump_config_builds_for_profile() {
        let (p, _d) = TestPlatform::new();
        let prof = vless();
        let id = prof.meta().id.clone();
        write_json_atomic(&p.paths().app_state, &default_app_state())
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![prof])
            .await
            .unwrap();
        let Response::Text(cfg) = dispatch(&p, Command::DumpConfig { profile_id: id })
            .await
            .unwrap()
        else {
            panic!()
        };
        let v: serde_json::Value = serde_json::from_str(&cfg).unwrap();
        assert!(v["outbounds"].is_array());
    }

    #[tokio::test]
    async fn dump_config_unknown_profile_errors() {
        let (p, _d) = TestPlatform::new();
        write_json_atomic(&p.paths().app_state, &default_app_state())
            .await
            .unwrap();
        let e = dispatch(
            &p,
            Command::DumpConfig {
                profile_id: "nope".into(),
            },
        )
        .await
        .unwrap_err();
        assert!(e.0.contains("profile not found"));
    }

    #[tokio::test]
    async fn parse_and_build_share_link_roundtrip() {
        let (p, _d) = TestPlatform::new();
        let Response::Profiles(profs) = dispatch(
            &p,
            Command::ParseShareLinks {
                text: "vless://11111111-1111-1111-1111-111111111111@e.example:443?type=tcp&security=tls&sni=s#Home".into(),
                group_id: None,
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert_eq!(profs.len(), 1);
        let Response::Text(link) = dispatch(
            &p,
            Command::BuildShareLink {
                profile: Box::new(profs[0].clone()),
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert!(link.starts_with("vless://"));
    }

    #[tokio::test]
    async fn download_asset_rejects_unsafe_filename() {
        let (p, _d) = TestPlatform::new();
        let e = dispatch(
            &p,
            Command::DownloadAsset {
                filename: "../escape".into(),
                url: "http://example".into(),
                mode: FetchMode::Direct,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(e.0, "invalid filename");
    }

    #[test]
    fn command_and_response_wire_shapes() {
        // Command is internally tagged on `cmd`; fields are camelCase.
        let c: Command = serde_json::from_value(serde_json::json!({
            "cmd": "fetchSubscription",
            "url": "https://x",
            "allowInsecure": true
        }))
        .unwrap();
        assert!(matches!(
            c,
            Command::FetchSubscription {
                allow_insecure: true,
                mode: FetchMode::Auto,
                ..
            }
        ));
        // Response is adjacently tagged kind/value.
        let v = serde_json::to_value(Response::Ports(vec![1, 2])).unwrap();
        assert_eq!(v, serde_json::json!({ "kind": "ports", "value": [1, 2] }));
        assert_eq!(
            serde_json::to_value(Response::Ok).unwrap(),
            serde_json::json!({ "kind": "ok" })
        );
    }
}
