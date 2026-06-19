//! The Linux desktop `Platform`: thin orchestration over the neutral lifecycle
//! steps, owning only the OS-specific parts — a native tun + `ip` routing. No
//! Magisk, no per-uid app filter.

use std::path::{Path, PathBuf};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::mpsc;

use kasumi_backend::fs::{exists, read_text, remove_file, write_text};
use kasumi_backend::fsjson::read_json;
use kasumi_backend::lifecycle::{random_tun_iface, spawn_core, spawn_tun2socks, verify_core_alive};
use kasumi_backend::net::ProxyStatus;
use kasumi_backend::platform::{
    BackendPaths, Engine, InstalledCores, Platform, PlatformCapabilities, StartDataPath,
    StopDataPath,
};
use kasumi_backend::proc::{kill_if_running, pid_matches_any, pid_matches_bin, read_pidfile};
use kasumi_core::contract::{RunState, ServiceState};
use kasumi_core::enums::CoreEngine;
use kasumi_core::state::{AppState, DEFAULT_LOCAL_HTTP_PORT, DEFAULT_LOCAL_SOCKS_PORT};

use super::network::run_watcher;
use super::paths::{DesktopPaths, FWMARK, IP};
use super::routing::{apply_xray_routing, clear_xray_routing, resolve_bypass_cidrs};
use super::silent;
use super::singbox::prepare_singbox_config;

pub struct DesktopPlatform {
    p: DesktopPaths,
}

impl DesktopPlatform {
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self {
            p: DesktopPaths::resolve()?,
        })
    }

    fn core_bin(&self, engine: CoreEngine) -> &str {
        match engine {
            CoreEngine::SingBox => &self.p.singbox_bin,
            CoreEngine::Xray => &self.p.xray_bin,
        }
    }

    async fn set_service_state(&self, value: &str) {
        let _ = write_text(&self.p.service_state_file, value).await;
    }

    async fn fail(&self, reason: &str) -> anyhow::Result<()> {
        self.set_service_state(&format!("failed:{reason}")).await;
        anyhow::bail!("{reason}")
    }

    async fn http_port(&self) -> u16 {
        read_json::<AppState>(&self.p.backend.app_state)
            .await
            .and_then(|s| s.settings.local_http_port)
            .unwrap_or(DEFAULT_LOCAL_HTTP_PORT)
    }

    async fn core_version(&self, engine: CoreEngine) -> Option<String> {
        let bin = self.core_bin(engine);
        if !exists(bin).await {
            return None;
        }
        let (code, out) = super::run_out(&[bin, "version"]).await;
        if code != 0 {
            return None;
        }
        out.lines()
            .next()
            .map(|l| l.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Which core is actually running (PID truth), or `None`.
    async fn running_engine(&self) -> Option<CoreEngine> {
        let pid = read_pidfile(&self.p.pidfile).await;
        if pid <= 0 {
            return None;
        }
        if pid_matches_bin(pid, &self.p.xray_bin).await {
            return Some(CoreEngine::Xray);
        }
        if pid_matches_bin(pid, &self.p.singbox_bin).await {
            return Some(CoreEngine::SingBox);
        }
        None
    }

    /// sing-box bring-up: it owns its own tun (auto_route) — no tun2socks/manual
    /// routing. The proxy-server bypass is baked into the config as
    /// `route_exclude_address` by `prepare_singbox_config`.
    async fn start_singbox(&self) -> anyhow::Result<()> {
        let cfg = self.p.backend.singbox_config.to_string_lossy().into_owned();
        let log = self
            .p
            .backend
            .log(kasumi_core::contract::LogTarget::Singbox);
        if !exists(&self.p.singbox_bin).await {
            return self.fail("sing-box binary missing").await;
        }
        if !exists(&cfg).await {
            return self.fail("config missing").await;
        }

        let cfg_text = read_text(&cfg).await.unwrap_or_default();
        let needed = kasumi_backend::lifecycle::referenced_srs(&cfg_text);
        let geo = Path::new(&self.p.geodat2srs_bin);
        let dat = self.p.backend.dat_dir.as_path();
        let srs = self.p.backend.srs_dir.as_path();
        kasumi_backend::lifecycle::sync_geo_asset("geoip", dat, srs, geo, &needed).await;
        kasumi_backend::lifecycle::sync_geo_asset("geosite", dat, srs, geo, &needed).await;
        if !kasumi_backend::lifecycle::missing_rule_sets(&cfg_text)
            .await
            .is_empty()
        {
            return self.fail("missing rule_set assets").await;
        }

        prepare_singbox_config(&cfg, &self.p.tun_iface_file, &self.p.tun2_iface_file).await?;

        let dat_dir = self.p.backend.dat_dir.to_string_lossy().into_owned();
        let child = spawn_core(&self.p.singbox_bin, &cfg, &log, &dat_dir, false).await?;
        let pid = child.id().unwrap_or(0) as i32;
        let _ = write_text(&self.p.pidfile, &pid.to_string()).await;
        if !verify_core_alive(pid, &self.p.singbox_bin, 6, Duration::from_millis(250)).await {
            return self
                .fail(&format!("core exited on startup — see {}", log.display()))
                .await;
        }
        Ok(())
    }

    /// xray bring-up: spawn xray (its own SOCKS), bridge a userspace tun to it via
    /// tun2socks, then install the Linux routing (server bypass + split-default).
    async fn start_xray(&self, socks_port: u16) -> anyhow::Result<()> {
        let cfg = self.p.backend.xray_config.to_string_lossy().into_owned();
        let log = self.p.backend.log(kasumi_core::contract::LogTarget::Xray);
        if !exists(&self.p.xray_bin).await {
            return self.fail("xray binary missing").await;
        }
        if !exists(&cfg).await {
            return self.fail("config missing").await;
        }

        // Resolve the server-bypass set before any tun route is up (needs DNS).
        let cfg_text = read_text(&cfg).await.unwrap_or_default();
        let bypass = resolve_bypass_cidrs(&cfg_text).await;

        let dat_dir = self.p.backend.dat_dir.to_string_lossy().into_owned();
        let child = spawn_core(&self.p.xray_bin, &cfg, &log, &dat_dir, false).await?;
        let pid = child.id().unwrap_or(0) as i32;
        let _ = write_text(&self.p.pidfile, &pid.to_string()).await;
        if !verify_core_alive(pid, &self.p.xray_bin, 6, Duration::from_millis(250)).await {
            return self
                .fail(&format!("core exited on startup — see {}", log.display()))
                .await;
        }

        let tun = random_tun_iface();
        let _ = write_text(&self.p.tun_iface_file, &tun).await;
        let t2s_log = self
            .p
            .backend
            .log(kasumi_core::contract::LogTarget::Tun2socks);
        let t2s =
            spawn_tun2socks(&self.p.tun2socks_bin, &tun, socks_port, &t2s_log, FWMARK).await?;
        let _ = write_text(
            &self.p.tun2socks_pidfile,
            &t2s.id().unwrap_or(0).to_string(),
        )
        .await;
        // tun2socks creates the tun device; wait for it before addressing/routing.
        for _ in 0..20 {
            if silent(&[IP, "link", "show", &tun]).await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        apply_xray_routing(&tun, &bypass, &self.p.route_state_file).await?;
        Ok(())
    }
}

impl Default for DesktopPlatform {
    fn default() -> Self {
        Self::new().expect("desktop paths resolve (HOME set)")
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RX/TX bytes for `iface` from /proc/net/dev, or (0, 0).
async fn iface_traffic(iface: Option<&str>) -> (u64, u64) {
    let Some(iface) = iface else {
        return (0, 0);
    };
    let Some(dev) = read_text("/proc/net/dev").await else {
        return (0, 0);
    };
    for line in dev.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() != iface {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        let rx = f.first().and_then(|x| x.parse().ok()).unwrap_or(0);
        let tx = f.get(8).and_then(|x| x.parse().ok()).unwrap_or(0);
        return (rx, tx);
    }
    (0, 0)
}

#[async_trait]
impl Platform for DesktopPlatform {
    fn paths(&self) -> &BackendPaths {
        &self.p.backend
    }

    async fn boot_init(&self) -> anyhow::Result<()> {
        // Unlike Android (RUN_DIR ⊂ DATADIR), the desktop runtime dir lives under
        // XDG_RUNTIME_DIR — a different base — so both must be created explicitly.
        let _ = tokio::fs::create_dir_all(&self.p.datadir).await;
        let _ = tokio::fs::create_dir_all(&self.p.run_dir).await;
        // Fresh start: seed the lifecycle channel so a stale value can't make status
        // lie before the first command.
        self.set_service_state("stopped").await;
        remove_file(&self.p.service_started_file).await;
        Ok(())
    }

    async fn start_data_path(&self, opts: StartDataPath) -> anyhow::Result<()> {
        let StartDataPath { engine, socks_port } = opts;
        self.set_service_state("connecting").await;
        let _ = write_text(&self.p.socks_port_file, &socks_port.to_string()).await;
        let result = if engine == CoreEngine::SingBox {
            self.start_singbox().await
        } else {
            self.start_xray(socks_port).await
        };
        match result {
            Ok(()) => {
                let _ = write_text(&self.p.service_started_file, &now_secs().to_string()).await;
                self.set_service_state("running").await;
                Ok(())
            }
            Err(e) => {
                // Roll back a half-built data-path; keep any "failed:<reason>" label.
                let cur = read_text(&self.p.service_state_file)
                    .await
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if !cur.starts_with("failed") {
                    self.set_service_state(&format!("failed:{e}")).await;
                }
                let _ = self
                    .stop_data_path(StopDataPath {
                        keep_service_state: true,
                    })
                    .await;
                Err(e)
            }
        }
    }

    async fn stop_data_path(&self, opts: StopDataPath) -> anyhow::Result<()> {
        // Stop the core first, gracefully: a sing-box auto_route core removes its
        // own ip rules + tun on SIGTERM. Then tear down the xray manual routing
        // (no-op for sing-box — no route-state file) and the tun2socks helper.
        kill_if_running(
            read_pidfile(&self.p.pidfile).await,
            None,
            &self.p.pidfile,
            true,
        )
        .await;
        clear_xray_routing(&self.p.route_state_file).await;
        kill_if_running(
            read_pidfile(&self.p.tun2socks_pidfile).await,
            Some(&self.p.tun2socks_bin),
            &self.p.tun2socks_pidfile,
            false,
        )
        .await;
        remove_file(&self.p.tun_iface_file).await;
        remove_file(&self.p.tun2_iface_file).await;
        if !opts.keep_service_state {
            self.set_service_state("stopped").await;
        }
        Ok(())
    }

    async fn service_state(&self) -> anyhow::Result<ServiceState> {
        let raw = read_text(&self.p.service_state_file)
            .await
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "stopped".into());
        let mut state = RunState::Stopped;
        let mut error = None;
        if raw.starts_with("failed") {
            state = RunState::Failed;
            let reason = raw
                .find(':')
                .map(|i| raw[i + 1..].to_string())
                .unwrap_or_default();
            error = (!reason.is_empty()).then_some(reason);
        } else if raw == "connecting" || raw == "running" {
            // "running" = process up; the Service's connectivity probe refines this
            // to Connected / NoInternet (see android platform).
            state = RunState::Connecting;
        }
        let tun = read_text(&self.p.tun_iface_file)
            .await
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let (rx, tx) = iface_traffic(tun.as_deref()).await;
        let started = read_pidfile(&self.p.service_started_file).await;
        let uptime_sec = if raw == "running" && started > 0 {
            now_secs().saturating_sub(started as u64)
        } else {
            0
        };
        Ok(ServiceState {
            state,
            error,
            download_bytes: rx,
            upload_bytes: tx,
            uptime_sec,
            engine: self.running_engine().await,
        })
    }

    async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
        let xray = self.core_version(CoreEngine::Xray).await;
        let singbox = self.core_version(CoreEngine::SingBox).await;
        let tun = exists("/dev/net/tun").await;
        Ok(PlatformCapabilities {
            cores: InstalledCores { xray, singbox },
            // Desktop fetches over reqwest, never a curl spawn.
            curl: false,
            tun,
            bridge: "desktop".into(),
        })
    }

    fn core_path(&self, engine: Engine) -> PathBuf {
        PathBuf::from(self.core_bin(engine))
    }

    async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
        let port = read_text(&self.p.socks_port_file)
            .await
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_LOCAL_SOCKS_PORT);
        let pid = read_pidfile(&self.p.pidfile).await;
        let running = pid > 0 && pid_matches_any(pid, &self.p.core_bins()).await;
        Ok(ProxyStatus {
            running,
            socks_port: port,
            http_port: self.http_port().await,
        })
    }

    fn tune_config(&self, engine: Engine, config: &mut Value) {
        if engine != CoreEngine::SingBox {
            return;
        }
        // Desktop runs sing-box as a root binary terminating from the tun fd: that
        // needs the gvisor stack. The "system" stack would require a kernel nftables
        // output redirect we don't set up here. (See singbox-gvisor-stack.)
        if let Some(inbounds) = config.get_mut("inbounds").and_then(Value::as_array_mut) {
            for ib in inbounds {
                if ib.get("type").and_then(Value::as_str) == Some("tun") {
                    ib["stack"] = Value::String("gvisor".into());
                }
            }
        }
    }

    fn watch_network_change(&self) -> Option<mpsc::Receiver<()>> {
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(run_watcher(tx));
        Some(rx)
    }

    async fn data_path_healthy(&self) -> Option<bool> {
        let core_pid = read_pidfile(&self.p.pidfile).await;
        if !(core_pid > 0 && pid_matches_any(core_pid, &self.p.core_bins()).await) {
            return Some(false);
        }
        // xray relies on a tun2socks helper; sing-box runs the tun itself.
        let engine = read_text(&self.p.engine_file)
            .await
            .map(|s| s.trim().to_string());
        if engine.as_deref() != Some("sing-box") {
            let t = read_pidfile(&self.p.tun2socks_pidfile).await;
            if !(t > 0 && pid_matches_bin(t, &self.p.tun2socks_bin).await) {
                return Some(false);
            }
        }
        Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn iface_traffic_handles_absent_iface() {
        assert_eq!(iface_traffic(None).await, (0, 0));
        assert_eq!(iface_traffic(Some("definitely-not-an-iface")).await, (0, 0));
    }

    #[test]
    fn now_secs_is_nonzero() {
        assert!(now_secs() > 0);
    }
}
