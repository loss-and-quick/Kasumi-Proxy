//! The tyed command surface both transports share. A [`Command`] carries its
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

use kasumi_core::chain::chain_candidates;
use kasumi_core::contract::{
    Capabilities, ConnectionProbe, CoreConflict, CoreResolution, FetchMode, HopConflict, LogTarget,
    ServiceState, TestKind, WsInfo,
};
use kasumi_core::core::{
    chain_conflicts, chain_forced_core, core_conflict, forced_core, preferred_core,
    rule_target_fallbacks, xray_only_settings,
};
use kasumi_core::core_config::{CoreConfig, build_core_config};
use kasumi_core::data_path_plan::AppRouting;
use kasumi_core::enums::{CoreEngine, wire_value};
use kasumi_core::import_input::{
    ResolvedImport, is_encrypted_url, resolve_import_text, subscription_fetch_url,
    withhold_unavailable,
};
use kasumi_core::mutate::{Backup, ImportMode, MutationIntent, apply_mutation};
use kasumi_core::profile::{Profile, Protocol};
use kasumi_core::request_identity::{IdentityInput, ResolvedIdentity};
use kasumi_core::share::{build_share_link, parse_share_links};
use kasumi_core::singbox_config::{apply_singbox_cache_file, matches_every_connection};
use kasumi_core::state::{
    AdvancedSettings, AppState, DEFAULT_LOG_ROTATE_KB, PortCollision, RoutingRule,
    default_app_state,
};
use kasumi_core::sub_changes::consented_keys;
use kasumi_core::sub_ingest::stored_for_url;
use kasumi_core::sub_policy::safe_provider_link;
use kasumi_log::{Area, ks_warn};

use crate::fs::{read_text, write_text};
use crate::fsjson::read_json;
use crate::net::{FetchUrlOptions, fetch_url, used_ports};
use crate::platform::{AppInfo, Platform};

/// First port `freePorts` probes when the caller doesn't pin a start.
const FREE_PORTS_BASE: u16 = kasumi_core::contract::TEST_PORT_BASE;
/// Default tail length for `log`.
const LOG_TAIL_LINES: usize = 200;

/// The variant name of a command — `Mutate`, `Status`, `Log` — without its payload.
/// A command carries the whole intent or profile it was asked about, which is far
/// too much for a log line, while "which command failed" is usually the question.
pub fn command_name(command: &Command) -> String {
    let rendered = format!("{command:?}");
    match rendered.find(['{', '(']) {
        Some(end) => rendered[..end].to_string(),
        None => rendered,
    }
}

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
    /// Restore a backup of any past schema: read as a [`Backup`] (migrated, with
    /// the profiles that still don't fit left out and counted), then applied as an
    /// `ImportBackup` intent. Routed through the `Service` like `Mutate`.
    ImportBackup {
        #[specta(type = Box<AppState>)]
        backup: Box<Backup>,
        mode: ImportMode,
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
    /// Sort pasted or scanned text into subscriptions, `happ://` links and share
    /// links (`import_input`), so the UI never re-implements the grammar.
    ResolveImportInput {
        text: String,
    },
    /// The URL an encrypted `happ://crypt` link leads to, for an explicit reveal.
    RevealSubscriptionUrl {
        url: String,
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
    /// Resolve which core each profile runs on (`core::resolve_core` under the
    /// persisted settings) plus its capability force, so the UI never re-implements
    /// the resolution matrix. Batch: one call covers a whole profile list.
    ResolveCores {
        profiles: Vec<Profile>,
    },
    /// Which stored profiles the given (possibly unsaved) profile can dial through,
    /// by `chain::chain_candidates` — the same check the config builders make, so
    /// the UI never re-implements chain validity.
    ChainCandidates {
        profile: Box<Profile>,
    },
    /// Of those candidates, the ones whose core requirement conflicts with the
    /// (possibly unsaved) profile's chain, by `core::chain_conflicts`.
    ChainConflicts {
        profile: Box<Profile>,
    },
    /// The local-port clash these (possibly unsaved) settings would have on this
    /// platform, by `AdvancedSettings::port_collision` — the check a settings
    /// write is refused by.
    CheckLocalPorts {
        settings: Box<AdvancedSettings>,
    },
    /// Which of these rules match every connection once built
    /// (`singbox_config::matches_every_connection`), so the UI can mark the
    /// rules they shadow without re-implementing the rule parser.
    CatchAllRules {
        rules: Vec<RoutingRule>,
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
    /// One connectivity check through the running core, on demand; replies with
    /// its round trip and the profile it measured (`Probe`). Stateful: it updates
    /// the Service's verdict.
    ProbeConnection,
    #[serde(rename_all = "camelCase")]
    CheckReadiness {
        #[serde(default)]
        profile_id: Option<String>,
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
    /// Open a provider link (support, web page, renewal) in the system browser.
    OpenUrl {
        url: String,
    },
    /// The request identity a subscription fetch sends. `input` previews unsaved
    /// settings; without it the stored ones are used. No `subId` = Settings alone.
    #[serde(rename_all = "camelCase")]
    ResolveRequestIdentity {
        #[serde(default)]
        sub_id: Option<String>,
        #[serde(default)]
        input: Option<Box<IdentityInput>>,
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
    /// Per-profile core resolutions, in the request's profile order.
    CoreResolutions(Vec<CoreResolution>),
    /// Profile ids, in stored order.
    ProfileIds(Vec<String>),
    /// Chain hops ruled out by a core conflict.
    HopConflicts(Vec<HopConflict>),
    /// Two local listeners on one port, or `null` when the ports are fine.
    PortCollision(Option<PortCollision>),
    /// One answer per item of the request, in its order.
    Flags(Vec<bool>),
    /// Latency in ms (tcp-ping and real-ping); `null` when there is no result.
    Ping(Option<i64>),
    Probe(ConnectionProbe),
    /// Throughput in bytes/sec; `null` when there is no result.
    Speed(Option<i64>),
    /// A bare acknowledgement (`{ok: true}` / no body in the old protocol).
    Ok,
    RequestIdentity(Box<ResolvedIdentity>),
    ImportInput(Box<ResolvedImport>),
    BackupRestored(Box<BackupRestored>),
    Readiness(Box<ReadinessReport>),
}

/// A restored backup: the new state and how many of its profiles were left out.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type)]
#[serde(rename_all = "camelCase")]
pub struct BackupRestored {
    pub state: AppState,
    pub skipped_profiles: u32,
}

/// A condition preventing or impeding proxy startup.
#[derive(Debug, Clone, Serialize, Deserialize, specta::Type, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ReadinessIssue {
    NoActiveProfile,
    CoreConflict { conflict: CoreConflict },
    PortCollision(PortCollision),
    MissingGeoAssets { assets: Vec<String> },
    ConfigError { message: String },
}

/// Unified startup readiness report for a profile under current settings and routes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, specta::Type, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessReport {
    pub profile_id: Option<String>,
    pub engine: Option<CoreEngine>,
    pub ok: bool,
    pub issues: Vec<ReadinessIssue>,
}

/// Reject path traversal / quoting tricks in asset filenames.
pub(crate) fn safe_filename(name: &str) -> bool {
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
    // The full read path (migration + normalization), so state written by an
    // older version builds with the same routes the UI shows.
    let state = crate::state::read_app_state(platform)
        .await
        .ok_or_else(|| err("app-state not found"))?;
    let profiles = &state.profiles;
    let profile = profiles
        .iter()
        .find(|p| p.meta().id == id)
        .ok_or_else(|| err(format!("profile not found: {id}")))?;
    refuse_unavailable(platform, profile, profiles)?;
    let rules = kasumi_core::route::resolve_route(&state, profile);
    let srs_dir = paths.srs_dir.to_str().unwrap_or("");
    let settings = &state.settings;
    let host = platform.host_traits();
    // The plan normalizes the proxy mode for the host, so a non-tun mode restored
    // from a desktop backup still builds the tun an Android data path needs.
    let mut built =
        build_core_config(profile, settings, &rules, profiles, srs_dir, host).map_err(err)?;
    if built.engine() == CoreEngine::SingBox {
        apply_singbox_cache_file(
            &mut built.config,
            &paths.singbox_cache().to_string_lossy(),
            settings,
        );
    }
    if host.app_routing == AppRouting::PerProcess {
        // Desktop: the per-app filter matches programs by executable (Android
        // routes its uid entries in the platform instead).
        kasumi_core::app_process::apply_process_filter(built.engine(), settings, &mut built.config);
    }
    platform.tune_config(built.engine(), &mut built.config);
    Ok(built)
}

/// A profile, or a hop of its chain, whose protocol this platform's cores can't
/// run fails here with the reason rather than as a core that dies on startup.
fn refuse_unavailable(
    platform: &dyn Platform,
    profile: &Profile,
    profiles: &[Profile],
) -> Result<(), CommandError> {
    let unavailable = platform.unavailable_protocols();
    if unavailable.is_empty() {
        return Ok(());
    }
    let hops = kasumi_core::chain::chain_hops(profile, profiles).unwrap_or_default();
    match std::iter::once(profile)
        .chain(hops)
        .find(|p| unavailable.contains(&p.protocol()))
    {
        Some(p) => Err(err(unavailable_reason(p))),
        None => Ok(()),
    }
}

fn unavailable_reason(p: &Profile) -> String {
    let name = &p.meta().remarks;
    match p.protocol() {
        Protocol::Naive => format!(
            "\"{name}\" is a Naive profile, which can't run on this device: \
             Naive isn't available on Android, where the bundled sing-box is built without it"
        ),
        other => format!(
            "\"{name}\" uses {}, which this device's cores can't run",
            wire_value(&other)
        ),
    }
}

/// Unified startup readiness check for a profile under current settings and routes.
pub(crate) async fn check_readiness(
    platform: &dyn Platform,
    profile_id: Option<&str>,
) -> Result<ReadinessReport, CommandError> {
    let state = crate::state::read_app_state(platform)
        .await
        .unwrap_or_else(default_app_state);

    let id = profile_id
        .filter(|s| !s.is_empty())
        .or(state.active_id.as_deref());
    let Some(id) = id else {
        return Ok(ReadinessReport {
            profile_id: None,
            engine: None,
            ok: false,
            issues: vec![ReadinessIssue::NoActiveProfile],
        });
    };
    let Some(profile) = state.profiles.iter().find(|p| p.meta().id == id) else {
        return Ok(ReadinessReport {
            profile_id: Some(id.to_string()),
            engine: None,
            ok: false,
            issues: vec![ReadinessIssue::NoActiveProfile],
        });
    };

    let mut issues = Vec::new();

    if let Some(c) = state
        .settings
        .port_collision(platform.supports_proxy_modes())
    {
        issues.push(ReadinessIssue::PortCollision(c));
    }

    let engine = match kasumi_core::core::resolve_core(profile, &state.settings, &state.profiles) {
        Ok(engine) => Some(engine),
        Err(conflict) => {
            issues.push(ReadinessIssue::CoreConflict { conflict });
            None
        }
    };

    if let Some(engine) = engine {
        match build_profile_config(platform, id).await {
            Ok(built) => {
                let cfg_text = serde_json::to_string_pretty(&built.config)
                    .map_err(|e| CommandError(e.to_string()))?;
                let missing = crate::lifecycle::missing_geo_assets(platform, engine, &cfg_text);
                if !missing.is_empty() {
                    issues.push(ReadinessIssue::MissingGeoAssets { assets: missing });
                }
            }
            Err(e) => {
                issues.push(ReadinessIssue::ConfigError { message: e.0 });
            }
        }
    }

    let ok = issues.is_empty();
    Ok(ReadinessReport {
        profile_id: Some(id.to_string()),
        engine,
        ok,
        issues,
    })
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
                    ..Default::default()
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
            crate::asset_update::download_asset(platform, &filename, &url, mode)
                .await
                .map_err(err)?;
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
                unavailable_protocols: platform.unavailable_protocols().to_vec(),
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
                return Ok(Response::Text(unwritten_log(
                    target,
                    &path,
                    lines,
                    &kasumi_log::recent(lines),
                )));
            };
            if txt.is_empty() {
                return Ok(Response::Text(unwritten_log(
                    target,
                    &path,
                    lines,
                    &kasumi_log::recent(lines),
                )));
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
            // The in-memory tail is part of what the viewer shows, so clearing the
            // files has to clear it too — or the user clears and still sees records.
            kasumi_log::buffer::clear();
            Ok(Response::Ok)
        }

        Command::RotateLogs { max_kb } => {
            let default_kb = crate::state::read_state_shell(&paths.app_state)
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
                // The shared trimmer, not a second implementation: it is the one the
                // boot path and the periodic tick use, so "how a log shrinks" is a
                // single answer. It cuts on a record boundary, which the old
                // char-boundary cut was free to break mid-record.
                match kasumi_log::rotate::trim_in_place(&path, limit as u64) {
                    Ok(()) => {}
                    Err(e) => {
                        ks_warn!(Area::Sys, "could not trim {}: {e}", path.display());
                    }
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

        Command::ParseShareLinks { text, group_id } => {
            let unavailable = platform.unavailable_protocols();
            let mut profiles = parse_share_links(&text, group_id.as_deref());
            profiles.retain(|p| !unavailable.contains(&p.protocol()));
            Ok(Response::Profiles(profiles))
        }

        Command::ResolveImportInput { text } => {
            let mut resolved = resolve_import_text(&text);
            withhold_unavailable(&mut resolved, platform.unavailable_protocols());
            Ok(Response::ImportInput(Box::new(resolved)))
        }

        Command::RevealSubscriptionUrl { url } => {
            if !is_encrypted_url(&url) {
                return Err(err("not an encrypted link"));
            }
            let plain = subscription_fetch_url(&url).map_err(|e| err(e.to_string()))?;
            Ok(Response::Text(plain.into_owned()))
        }

        Command::BuildShareLink { profile } => Ok(Response::Text(build_share_link(&profile))),

        Command::OpenUrl { url } => {
            // The link came from a provider: only public http(s) reaches the OS.
            let url = safe_provider_link(&url).ok_or_else(|| err("refusing to open this link"))?;
            platform
                .open_url(&url)
                .await
                .map_err(|e| err(e.to_string()))?;
            Ok(Response::Ok)
        }

        Command::ResolveRequestIdentity { sub_id, input } => {
            let state = crate::state::read_app_state(platform)
                .await
                .unwrap_or_else(default_app_state);
            let sub = sub_id
                .as_deref()
                .and_then(|id| state.subscriptions.iter().find(|s| s.id == id));
            let input = input
                .map(|i| *i)
                .unwrap_or_else(|| IdentityInput::stored(&state.settings.request_identity, sub));
            // The keys the next fetch of this subscription would be built with.
            let stored = match sub {
                Some(s) => crate::sub_meta::read_all(platform).await.remove(&s.id),
                None => None,
            };
            let meta = sub
                .and_then(|s| stored_for_url(stored.as_ref(), &s.url))
                .map(|s| &s.meta);
            let consented = sub.map_or_else(Vec::new, |s| consented_keys(s, meta));
            let resolved =
                crate::identity::resolve_request(platform, &input, meta, &consented).await;
            Ok(Response::RequestIdentity(Box::new(resolved.view)))
        }

        Command::ChainCandidates { profile } => {
            let profiles: Vec<Profile> = read_json(&paths.profiles).await.unwrap_or_default();
            Ok(Response::ProfileIds(chain_candidates(&profile, &profiles)))
        }

        Command::ChainConflicts { profile } => {
            let profiles: Vec<Profile> = read_json(&paths.profiles).await.unwrap_or_default();
            Ok(Response::HopConflicts(chain_conflicts(&profile, &profiles)))
        }

        Command::CheckLocalPorts { settings } => Ok(Response::PortCollision(
            settings.port_collision(platform.supports_proxy_modes()),
        )),

        Command::CatchAllRules { rules } => Ok(Response::Flags(
            rules.iter().map(matches_every_connection).collect(),
        )),

        Command::ResolveCores { profiles } => {
            let settings = crate::state::read_state_shell(&paths.app_state)
                .await
                .map(|s| s.settings)
                .unwrap_or_default();
            // The given profiles may be unsaved drafts: they stand in for their
            // stored copies while the chains are walked.
            let mut all: Vec<Profile> = read_json(&paths.profiles).await.unwrap_or_default();
            all.retain(|s| !profiles.iter().any(|p| p.meta().id == s.meta().id));
            all.extend(profiles.iter().cloned());
            Ok(Response::CoreResolutions(
                profiles
                    .iter()
                    .map(|p| {
                        let (resolved, forced, forced_by_hop, conflict) =
                            match chain_forced_core(p, &all) {
                                Ok(Some((engine, by))) => (
                                    engine,
                                    Some(engine),
                                    (by.meta().id != p.meta().id)
                                        .then(|| by.meta().remarks.clone()),
                                    core_conflict(p),
                                ),
                                Ok(None) => {
                                    (preferred_core(p, &settings), None, None, core_conflict(p))
                                }
                                Err(c) => {
                                    let own = forced_core(p);
                                    let resolved =
                                        own.unwrap_or_else(|| preferred_core(p, &settings));
                                    (resolved, own, None, Some(c))
                                }
                            };
                        CoreResolution {
                            resolved,
                            forced,
                            forced_by_hop,
                            conflict,
                            sees_processes: kasumi_core::app_process::sees_processes(
                                resolved, &settings,
                            ),
                            rule_target_fallback: rule_target_fallbacks(p),
                            xray_only_settings: xray_only_settings(p),
                        }
                    })
                    .collect(),
            ))
        }

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
        Command::CheckReadiness { profile_id } => {
            let report = check_readiness(platform, profile_id.as_deref()).await?;
            Ok(Response::Readiness(Box::new(report)))
        }

        Command::Mutate { .. }
        | Command::ImportBackup { .. }
        | Command::Start { .. }
        | Command::Stop
        | Command::Restart { .. }
        | Command::ReloadAppFilter
        | Command::ApplySubscription { .. }
        | Command::ProbeConnection => Err(err(
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
    // A write may not introduce a port clash: the core (or the PAC server) would
    // fail to bind only at the next start. A clash already on disk doesn't block
    // unrelated edits.
    let pac = platform.supports_proxy_modes();
    if let Some(clash) = next.settings.port_collision(pac)
        && prev.settings.port_collision(pac) != Some(clash)
    {
        return Err(err(clash.to_string()));
    }
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
/// ([`run_mutation`]) and the headless fetch paths ([`crate::sub_update`],
/// [`crate::asset_update`]) — so the chain is the one place invariants are
/// enforced, on every write.
pub(crate) async fn persist_with_chain(
    platform: &dyn Platform,
    prev: &AppState,
    next: &mut AppState,
) -> std::io::Result<()> {
    crate::state_mw::default_chain().run(prev, next);
    crate::state::write_app_state(platform, next).await?;
    // Every write carries the settings, so this is where a changed log level
    // reaches the running process — the UI's setting must not need a restart.
    crate::state::apply_app_log_level(platform).await;
    // Whichever path dropped a profile (UI delete, provider refresh, backup
    // replace), its retained test logs go with it.
    crate::jobs::remove_dropped_test_logs(platform, prev, next).await;
    Ok(())
}

/// Every log file the app keeps, in the order the viewer lists them.
pub const LOG_TARGETS: [LogTarget; 4] = [
    LogTarget::Daemon,
    LogTarget::Xray,
    LogTarget::Singbox,
    LogTarget::TunEngine,
];

/// What the viewer shows for a log file that has nothing in it. The app's own log
/// has a fallback: the facade keeps the last records in memory, which is the only
/// place a crash during boot is visible — the file is written by the very first
/// thing that failed. The core logs have no such window, so they say so plainly.
/// `buffered` is passed in rather than read here, so the decision can be tested
/// without the process-wide buffer other tests are writing to.
fn unwritten_log(target: LogTarget, path: &Path, lines: usize, buffered: &[String]) -> String {
    let reason = if path.exists() {
        format!("(empty log: {})", path.display())
    } else {
        format!("(no log: {})", path.display())
    };
    if target != LogTarget::Daemon || buffered.is_empty() {
        return reason;
    }
    let shown = &buffered[buffered.len().saturating_sub(lines)..];
    format!(
        "{reason}\n--- {} record(s) this session, not yet on disk ---\n{}",
        shown.len(),
        shown.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsjson::write_json_atomic;
    use crate::testutil::{TestPlatform, sample_vless as vless};
    use kasumi_core::contract::RunState;
    use kasumi_core::state::DEFAULT_LOCAL_SOCKS_PORT;

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
    async fn a_wholesale_replace_is_stored_at_the_current_schema() {
        let (p, _d) = TestPlatform::new();
        // The UI's hydrate sends its state without `schemaVersion`.
        let mut sent = serde_json::to_value(default_app_state()).unwrap();
        sent.as_object_mut().unwrap().remove("schemaVersion");
        let intent: MutationIntent =
            serde_json::from_value(serde_json::json!({ "kind": "replaceState", "state": sent }))
                .unwrap();
        run_mutation(&p, &intent).await.unwrap();
        let doc: serde_json::Value = crate::fsjson::read_json(&p.paths().app_state)
            .await
            .unwrap();
        assert_eq!(doc["schemaVersion"], kasumi_core::migrate::SCHEMA_VERSION);
    }

    #[tokio::test]
    async fn open_url_rejects_non_http() {
        let (p, _d) = TestPlatform::new();
        let open = |url: &str| {
            dispatch(
                &p,
                Command::OpenUrl {
                    url: url.to_owned(),
                },
            )
        };
        for url in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "intent://x#Intent;end",
            "http://192.168.1.1/",
            "https://localhost/",
        ] {
            let e = open(url).await.unwrap_err();
            assert!(e.0.contains("refusing"), "{url}: {e}");
        }
        // A public link passes the check and reaches the platform, which has no
        // browser in tests.
        let e = open("https://example.org/renew").await.unwrap_err();
        assert!(e.0.contains("not supported"), "{e}");
    }

    #[tokio::test]
    async fn resolve_request_identity_previews_with_the_provider_keys() {
        use kasumi_core::request_identity::{HwidSource, IdentityInput};
        use kasumi_core::state::Subscription;
        use kasumi_core::sub_ingest::StoredSubMeta;

        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        state.subscriptions = vec![Subscription {
            id: "s1".into(),
            url: "https://sub.example.org/s".into(),
            ..Default::default()
        }];
        crate::state::write_app_state(&p, &state).await.unwrap();
        let mut meta = happ_sub::MetaMap::new();
        meta.insert("subscription-send-hwid-enabled", "false");
        let stored = StoredSubMeta {
            source_url: "https://sub.example.org/s".into(),
            meta,
            ..Default::default()
        };
        crate::sub_meta::write_entry(&p, "s1", Some(stored), &["s1"])
            .await
            .unwrap();
        let resolve = |sub_id: Option<&str>, input: Option<Box<IdentityInput>>| {
            dispatch(
                &p,
                Command::ResolveRequestIdentity {
                    sub_id: sub_id.map(str::to_owned),
                    input,
                },
            )
        };
        let view = |r: Response| match r {
            Response::RequestIdentity(v) => *v,
            other => panic!("{other:?}"),
        };
        let names = |v: &ResolvedIdentity| -> Vec<String> {
            v.headers.iter().map(|h| h.name.clone()).collect()
        };

        let v = view(resolve(Some("s1"), None).await.unwrap());
        assert!(v.provider_hides_device);
        assert_eq!(names(&v), ["Connection", "User-agent", "X-Device-Locale"]);
        assert_eq!(v.hwid_source, HwidSource::HappDeviceId);

        let mut input = IdentityInput::stored(&state.settings.request_identity, None);
        input.request.send_hwid = Some(true);
        input.request.hwid = Some("typed-hwid".into());
        let v = view(resolve(Some("s1"), Some(Box::new(input))).await.unwrap());
        assert!(names(&v).contains(&"X-HWID".to_owned()));
        assert_eq!(
            (v.hwid.as_str(), v.hwid_source),
            ("typed-hwid", HwidSource::Subscription)
        );

        let v = view(resolve(None, None).await.unwrap());
        assert!(!v.provider_hides_device);
        assert_eq!(v.headers.len(), 7);
    }

    #[tokio::test]
    async fn settings_write_with_clashing_ports_is_refused() {
        let (p, _d) = TestPlatform::new();
        let set = |settings: AdvancedSettings| MutationIntent::SetSettings {
            settings: Box::new(settings),
        };
        let clashing = AdvancedSettings {
            local_http_port: Some(DEFAULT_LOCAL_SOCKS_PORT),
            ..Default::default()
        };
        let e = run_mutation(&p, &set(clashing.clone())).await.unwrap_err();
        assert_eq!(e.0, "the SOCKS and HTTP ports are both 10808");
        // Nothing was written.
        let Response::State(state) = dispatch(&p, Command::ReadState).await.unwrap() else {
            panic!()
        };
        assert_eq!(state.settings.local_http_port, None);

        let Response::PortCollision(check) = dispatch(
            &p,
            Command::CheckLocalPorts {
                settings: Box::new(clashing),
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert_eq!(check.map(|c| c.port), Some(DEFAULT_LOCAL_SOCKS_PORT));

        // A PAC port means nothing where no PAC server runs.
        let pac_on_socks = AdvancedSettings {
            local_pac_port: Some(DEFAULT_LOCAL_SOCKS_PORT),
            ..Default::default()
        };
        assert!(!p.supports_proxy_modes());
        run_mutation(&p, &set(pac_on_socks)).await.unwrap();
    }

    #[tokio::test]
    async fn catch_all_rules_answers_per_rule() {
        let (p, _d) = TestPlatform::new();
        let rule = |domain: &str| RoutingRule {
            id: domain.into(),
            remarks: String::new(),
            enabled: true,
            outbound_tag: "direct".into(),
            domain: Some(vec![domain.into()]).filter(|_| !domain.is_empty()),
            ip: None,
            port: Some("0-65535".into()),
            network: None,
            protocol: None,
            process: None,
            package_name: None,
            source_ip: None,
        };
        // A commented-out domain leaves the rule out instead of widening it.
        let rules = vec![rule("example.com"), rule("# example.com"), rule("")];
        let Response::Flags(flags) = dispatch(&p, Command::CatchAllRules { rules })
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(flags, [false, false, true]);
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

    #[test]
    fn an_empty_app_log_falls_back_to_what_is_still_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        std::fs::write(&path, "").unwrap();
        let buffered = [
            "2026-02-11T09:14:02.131+00:00 +0.001s INFO  kasumi::sys daemon starting".to_string(),
            "2026-02-11T09:14:02.140+00:00 +0.002s WARN  kasumi::platform boot init failed"
                .to_string(),
        ];

        let text = unwritten_log(LogTarget::Daemon, &path, 10, &buffered);
        assert!(
            text.starts_with(&format!("(empty log: {})", path.display())),
            "{text}"
        );
        assert!(
            text.contains("--- 2 record(s) this session, not yet on disk ---"),
            "{text}"
        );
        assert!(text.contains("daemon starting"), "{text}");

        // The tail the viewer asked for, and only the app's own log falls back.
        let text = unwritten_log(LogTarget::Daemon, &path, 1, &buffered);
        assert!(text.contains("boot init failed"), "{text}");
        assert!(!text.contains("daemon starting"), "{text}");
        let text = unwritten_log(LogTarget::Xray, &path, 10, &buffered);
        assert_eq!(text, format!("(empty log: {})", path.display()));

        // A core log that was never written, and an app log with nothing buffered. A
        // daemon.log that does not exist yet falls back all the same — that is the
        // boot crash this exists for.
        let missing = dir.path().join("xray.log");
        let text = unwritten_log(LogTarget::Daemon, &missing, 10, &buffered);
        assert!(text.starts_with("(no log:"), "{text}");
        assert!(text.contains("daemon starting"), "{text}");
        assert_eq!(
            unwritten_log(LogTarget::Daemon, &path, 10, &[]),
            format!("(empty log: {})", path.display())
        );
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

    const NAIVE_LINK: &str = "naive+https://u:p@n.example:443#Naive";

    #[tokio::test]
    async fn capabilities_list_the_protocols_the_cores_cannot_run() {
        let (p, _d) = TestPlatform::new();
        p.set_unavailable(&[Protocol::Naive]);
        let Response::Capabilities(c) = dispatch(&p, Command::Capabilities).await.unwrap() else {
            panic!()
        };
        assert_eq!(c.unavailable_protocols, [Protocol::Naive]);
    }

    #[tokio::test]
    async fn imports_set_aside_links_the_device_cannot_run() {
        let (p, _d) = TestPlatform::new();
        p.set_unavailable(&[Protocol::Naive]);
        let vless = "vless://11111111-1111-1111-1111-111111111111@e.example:443?type=tcp&security=tls&sni=s#Home";
        let text = format!("{vless}\n{NAIVE_LINK}");
        let Response::ImportInput(r) =
            dispatch(&p, Command::ResolveImportInput { text: text.clone() })
                .await
                .unwrap()
        else {
            panic!()
        };
        assert_eq!(r.share_text, vless);
        assert_eq!(r.unsupported.len(), 1);
        assert_eq!(
            r.unsupported[0].kind,
            kasumi_core::import_input::UnsupportedInput::UnavailableProtocol
        );

        // The parser never hands back a profile that couldn't start either.
        let Response::Profiles(profiles) = dispatch(
            &p,
            Command::ParseShareLinks {
                text,
                group_id: None,
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].protocol(), Protocol::Vless);
    }

    // A naive profile already in the state (a backup, an older build) is refused
    // with the reason instead of a core that dies on startup, also as a hop.
    #[tokio::test]
    async fn starting_an_unavailable_protocol_says_why() {
        let (p, _d) = TestPlatform::new();
        p.set_unavailable(&[Protocol::Naive]);
        let naive = kasumi_core::share::parse_share_link(NAIVE_LINK, None).unwrap();
        let mut exit = vless();
        exit.meta_mut().via = Some(naive.meta().id.clone());
        write_json_atomic(&p.paths().app_state, &default_app_state())
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![naive.clone(), exit.clone()])
            .await
            .unwrap();
        for id in [naive.meta().id.clone(), exit.meta().id.clone()] {
            let e = build_profile_config(&p, &id).await.unwrap_err();
            assert!(e.0.contains("Naive isn't available on Android"), "{}", e.0);
        }
    }

    #[tokio::test]
    async fn resolve_import_input_and_reveal_an_encrypted_link() {
        let (p, _d) = TestPlatform::new();
        let link = crate::testutil::crypt1_link("https://sub.example.com/s?t=1");
        let text = format!("{link}\nhapp://add/https://a.example/s\nhapp://toggle\nvless://x");
        let Response::ImportInput(r) = dispatch(&p, Command::ResolveImportInput { text })
            .await
            .unwrap()
        else {
            panic!()
        };
        let subs: Vec<(&str, bool)> = r
            .subscriptions
            .iter()
            .map(|s| (s.url.as_str(), s.encrypted))
            .collect();
        assert_eq!(
            subs,
            [(link.as_str(), true), ("https://a.example/s", false)]
        );
        assert_eq!(r.unsupported.len(), 1);
        assert_eq!(r.share_text, "vless://x");

        let Response::Text(url) = dispatch(&p, Command::RevealSubscriptionUrl { url: link })
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(url, "https://sub.example.com/s?t=1");
        let incy = crate::testutil::incy_link("https://sub.example.com/i", None);
        let Response::Text(url) = dispatch(&p, Command::RevealSubscriptionUrl { url: incy })
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(url, "https://sub.example.com/i");
        let plain = "https://sub.example.com/s".to_owned();
        assert!(
            dispatch(&p, Command::RevealSubscriptionUrl { url: plain })
                .await
                .is_err()
        );
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
    async fn chain_candidates_checks_the_draft_against_stored_profiles() {
        use kasumi_core::share::parse_share_link;

        let (p, _d) = TestPlatform::new();
        let mut a = parse_share_link("trojan://pw@a.ex:443#A", None).unwrap();
        a.meta_mut().id = "a".into();
        let mut b = parse_share_link("trojan://pw@b.ex:443#B", None).unwrap();
        b.meta_mut().id = "b".into();
        b.meta_mut().via = Some("a".into());
        write_json_atomic(&p.paths().profiles, &vec![a.clone(), b])
            .await
            .unwrap();

        // b already dials through a, so a has nothing left to dial through.
        let Response::ProfileIds(ids) = dispatch(
            &p,
            Command::ChainCandidates {
                profile: Box::new(a),
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert!(ids.is_empty(), "{ids:?}");

        // A new draft may dial through either.
        let draft = parse_share_link("trojan://pw@n.ex:443#N", None).unwrap();
        let Response::ProfileIds(ids) = dispatch(
            &p,
            Command::ChainCandidates {
                profile: Box::new(draft),
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert_eq!(ids, ["a", "b"]);
    }

    #[tokio::test]
    async fn chain_conflicts_lists_stored_hops_on_the_other_core() {
        use kasumi_core::share::parse_share_link;

        let (p, _d) = TestPlatform::new();
        let mut tuic = parse_share_link("tuic://u:pw@t.ex:443?sni=t.ex#T", None).unwrap();
        tuic.meta_mut().id = "tuic".into();
        let mut plain = parse_share_link("trojan://pw@p.ex:443#P", None).unwrap();
        plain.meta_mut().id = "plain".into();
        write_json_atomic(&p.paths().profiles, &vec![tuic, plain])
            .await
            .unwrap();
        let mut draft =
            parse_share_link("vless://u@e.x:443?type=xhttp&security=tls#E", None).unwrap();
        draft.meta_mut().id = "draft".into();

        let Response::HopConflicts(found) = dispatch(
            &p,
            Command::ChainConflicts {
                profile: Box::new(draft),
            },
        )
        .await
        .unwrap() else {
            panic!()
        };
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "tuic");
    }

    #[tokio::test]
    async fn resolve_cores_returns_resolution_per_profile() {
        use kasumi_core::enums::CoreEngine;
        use kasumi_core::share::parse_share_link;

        let (p, _d) = TestPlatform::new();
        // No app-state on disk: default settings apply.
        let profiles = vec![
            // tuic is sing-box-only → forced.
            parse_share_link("tuic://u:pw@t.ex:443?sni=t.ex", None).unwrap(),
            // plain vless tcp+tls is selectable → default table (xray), no force.
            parse_share_link("vless://u@e.x:443?type=tcp&security=tls", None).unwrap(),
            // reality+pqv is an xray-only capability → forced.
            parse_share_link(
                "vless://u@e.x:443?type=tcp&security=reality&pbk=PK&sni=s&pqv=Q",
                None,
            )
            .unwrap(),
            // xhttp is xray-only, and xray can't skip the certificate check → conflict.
            parse_share_link(
                "vless://u@e.x:443?type=xhttp&security=tls&sni=e.x&allowInsecure=1",
                None,
            )
            .unwrap(),
        ];
        let Response::CoreResolutions(rs) = dispatch(&p, Command::ResolveCores { profiles })
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(rs.len(), 4);
        assert!(rs[..3].iter().all(|r| r.conflict.is_none()), "{rs:?}");
        assert_eq!(
            rs[3].conflict,
            Some(kasumi_core::contract::CoreConflict::UnpinnedInsecureTls)
        );
        assert_eq!(rs[0].resolved, CoreEngine::SingBox);
        assert_eq!(rs[0].forced, Some(CoreEngine::SingBox));
        assert_eq!(rs[1].resolved, CoreEngine::Xray);
        assert_eq!(rs[1].forced, None);
        assert_eq!(rs[2].resolved, CoreEngine::Xray);
        assert_eq!(rs[2].forced, Some(CoreEngine::Xray));

        use kasumi_core::contract::TargetFallback;
        let fallbacks: Vec<_> = rs.iter().map(|r| &r.rule_target_fallback).collect();
        assert_eq!(
            fallbacks[0].get(&CoreEngine::Xray),
            Some(&TargetFallback::SingBoxOnly)
        );
        assert!(fallbacks[1].is_empty() && fallbacks[2].is_empty());
        assert_eq!(
            fallbacks[3].get(&CoreEngine::Xray),
            Some(&TargetFallback::CantStart {
                conflict: kasumi_core::contract::CoreConflict::UnpinnedInsecureTls
            })
        );
    }

    #[tokio::test]
    async fn resolve_cores_follows_the_proxy_chain() {
        use kasumi_core::contract::CoreConflict;
        use kasumi_core::enums::CoreEngine;
        use kasumi_core::share::parse_share_link;

        let named = |uri: &str, id: &str, via: Option<&str>| {
            let mut p = parse_share_link(uri, None).unwrap();
            p.meta_mut().id = id.into();
            p.meta_mut().remarks = id.into();
            p.meta_mut().via = via.map(str::to_owned);
            p
        };
        let (p, _d) = TestPlatform::new();
        let stored = vec![named("tuic://u:pw@t.ex:443?sni=t.ex", "hop", None)];
        write_json_atomic(&p.paths().profiles, &stored)
            .await
            .unwrap();

        // An unsaved draft dialing through the stored sing-box-only hop.
        let drafts = vec![
            named(
                "vless://u@e.x:443?type=tcp&security=tls",
                "draft",
                Some("hop"),
            ),
            named(
                "vless://u@e.x:443?type=xhttp&security=tls",
                "xhttp",
                Some("hop"),
            ),
        ];
        let Response::CoreResolutions(rs) =
            dispatch(&p, Command::ResolveCores { profiles: drafts })
                .await
                .unwrap()
        else {
            panic!()
        };
        assert_eq!(rs[0].resolved, CoreEngine::SingBox);
        assert_eq!(rs[0].forced, Some(CoreEngine::SingBox));
        assert_eq!(rs[0].forced_by_hop.as_deref(), Some("hop"));
        assert_eq!(rs[0].conflict, None);

        assert_eq!(rs[1].resolved, CoreEngine::Xray);
        assert_eq!(
            rs[1].conflict,
            Some(CoreConflict::ChainCoreConflict {
                xray: "xhttp".into(),
                sing_box: "hop".into(),
            })
        );
    }

    #[tokio::test]
    async fn resolve_cores_honours_persisted_core_table() {
        use kasumi_core::enums::CoreEngine;
        use kasumi_core::profile::Protocol;
        use kasumi_core::share::parse_share_link;

        let (p, _d) = TestPlatform::new();
        let mut state = default_app_state();
        state
            .settings
            .core_by_protocol
            .insert(Protocol::Vless, CoreEngine::SingBox);
        write_json_atomic(&p.paths().app_state, &state)
            .await
            .unwrap();
        let profiles =
            vec![parse_share_link("vless://u@e.x:443?type=tcp&security=tls", None).unwrap()];
        let Response::CoreResolutions(rs) = dispatch(&p, Command::ResolveCores { profiles })
            .await
            .unwrap()
        else {
            panic!()
        };
        // Selectable profile follows the persisted coreByProtocol table.
        assert_eq!(rs[0].resolved, CoreEngine::SingBox);
        assert_eq!(rs[0].forced, None);
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

    #[tokio::test]
    async fn check_readiness_no_active_profile() {
        let (p, _d) = TestPlatform::new();
        write_json_atomic(&p.paths().app_state, &default_app_state())
            .await
            .unwrap();
        let res = dispatch(&p, Command::CheckReadiness { profile_id: None })
            .await
            .unwrap();
        let Response::Readiness(report) = res else {
            panic!("expected Readiness response");
        };
        assert!(!report.ok);
        assert_eq!(report.profile_id, None);
        assert_eq!(report.engine, None);
        assert_eq!(report.issues, vec![ReadinessIssue::NoActiveProfile]);

        let res = dispatch(
            &p,
            Command::CheckReadiness {
                profile_id: Some("nonexistent".into()),
            },
        )
        .await
        .unwrap();
        let Response::Readiness(report) = res else {
            panic!("expected Readiness response");
        };
        assert!(!report.ok);
        assert_eq!(report.profile_id, Some("nonexistent".into()));
        assert_eq!(report.engine, None);
        assert_eq!(report.issues, vec![ReadinessIssue::NoActiveProfile]);
    }

    #[tokio::test]
    async fn check_readiness_port_collision() {
        let (p, _d) = TestPlatform::new();
        let prof = vless();
        let id = prof.meta().id.clone();
        let mut state = default_app_state();
        state.active_id = Some(id);
        state.settings.local_http_port = Some(DEFAULT_LOCAL_SOCKS_PORT);
        write_json_atomic(&p.paths().app_state, &state)
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![prof])
            .await
            .unwrap();

        let res = dispatch(&p, Command::CheckReadiness { profile_id: None })
            .await
            .unwrap();
        let Response::Readiness(report) = res else {
            panic!("expected Readiness response");
        };
        assert!(!report.ok);
        assert!(
            report
                .issues
                .iter()
                .any(|i| matches!(i, ReadinessIssue::PortCollision(_)))
        );
    }

    #[tokio::test]
    async fn check_readiness_missing_geo_assets() {
        use kasumi_core::route::{RouteBlockRef, RuleBlock};
        use kasumi_core::state::RoutingMode;

        let (p, _d) = TestPlatform::new();
        let prof = vless();
        let id = prof.meta().id.clone();
        let mut state = default_app_state();
        state.active_id = Some(id.clone());
        state.settings.routing_mode = RoutingMode::Rules;
        let rule = RoutingRule {
            id: "r1".into(),
            remarks: "geo rule".into(),
            enabled: true,
            outbound_tag: "direct".into(),
            domain: Some(vec!["geosite:ru".into()]),
            ip: None,
            port: None,
            network: None,
            protocol: None,
            process: None,
            package_name: None,
            source_ip: None,
        };
        state.rule_blocks = vec![RuleBlock {
            id: "b1".into(),
            name: "block1".into(),
            rules: vec![rule],
            source_sub_id: None,
        }];
        state.routes[0].blocks = vec![RouteBlockRef {
            block_id: "b1".into(),
            enabled: true,
        }];
        write_json_atomic(&p.paths().app_state, &state)
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![prof])
            .await
            .unwrap();

        let res = dispatch(&p, Command::CheckReadiness { profile_id: None })
            .await
            .unwrap();
        let Response::Readiness(report) = res else {
            panic!("expected Readiness response");
        };
        assert!(!report.ok);
        assert_eq!(
            report.issues,
            vec![ReadinessIssue::MissingGeoAssets {
                assets: vec!["geosite.dat".into()]
            }]
        );
    }

    #[tokio::test]
    async fn check_readiness_clean_ok() {
        let (p, _d) = TestPlatform::new();
        let prof = vless();
        let id = prof.meta().id.clone();
        let mut state = default_app_state();
        state.active_id = Some(id.clone());
        write_json_atomic(&p.paths().app_state, &state)
            .await
            .unwrap();
        write_json_atomic(&p.paths().profiles, &vec![prof])
            .await
            .unwrap();

        let res = dispatch(&p, Command::CheckReadiness { profile_id: None })
            .await
            .unwrap();
        let Response::Readiness(report) = res else {
            panic!("expected Readiness response");
        };
        assert!(report.ok);
        assert!(report.issues.is_empty());
        assert!(report.engine.is_some());
    }
}
