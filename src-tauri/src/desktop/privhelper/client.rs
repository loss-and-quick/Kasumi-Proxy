//! GUI side of privilege separation: a thin transport that sends a [`PrivRequest`]
//! and reads back its one [`PrivReply`] over the helper's unix socket.
//!
//! The connection is held open and guarded by a mutex, so concurrent `Platform`
//! calls from the Service serialize into ordered request/reply pairs (the framing
//! is positional — one reply per request). `RemotePlatform`, which implements
//! `Platform` on top of this, is wired up where the GUI builds its Service.

use anyhow::Context;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use super::proto::{PrivReply, PrivRequest};
use super::transport::{self, BoxRead, BoxWrite};

/// A held-open connection to the privilege helper.
pub struct Client {
    inner: Mutex<Conn>,
}

struct Conn {
    reader: tokio::io::Lines<BufReader<BoxRead>>,
    writer: BoxWrite,
}

impl Client {
    /// Connect to the helper listening at `addr` (a unix-socket path on Linux, a
    /// named-pipe name on Windows).
    pub async fn connect(addr: &str) -> anyhow::Result<Self> {
        let (read, writer) = transport::connect(addr).await?;
        Ok(Self {
            inner: Mutex::new(Conn {
                reader: BufReader::new(read).lines(),
                writer,
            }),
        })
    }

    /// Send one request and await its reply. A `PrivReply::Err` from the helper is
    /// surfaced as an `Err` so callers see failures as failures.
    pub async fn call(&self, req: PrivRequest) -> anyhow::Result<PrivReply> {
        let reply = self.call_raw(req).await?;
        if let PrivReply::Err { message } = reply {
            anyhow::bail!("{message}");
        }
        Ok(reply)
    }

    /// Send one request and return the raw reply, including `PrivReply::Err`.
    pub async fn call_raw(&self, req: PrivRequest) -> anyhow::Result<PrivReply> {
        let mut conn = self.inner.lock().await;
        let mut line = serde_json::to_vec(&req)?;
        line.push(b'\n');
        conn.writer.write_all(&line).await?;
        conn.writer.flush().await?;
        let resp = conn
            .reader
            .next_line()
            .await?
            .context("privilege helper closed the connection")?;
        Ok(serde_json::from_str::<PrivReply>(&resp)?)
    }
}

// The end-to-end round-trip binds a real unix socket via `server::serve`; the
// Windows pipe path is exercised by the desktop-windows CI build, not here.
#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::Value;

    use kasumi_backend::net::ProxyStatus;
    use kasumi_backend::platform::{
        BackendPaths, Engine, InstalledCores, Platform, PlatformCapabilities, StartDataPath,
        StopDataPath,
    };
    use kasumi_core::contract::{RunState, ServiceState};
    use kasumi_core::enums::CoreEngine;

    use super::super::proto::{PrivReply, PrivRequest};
    use super::super::server;
    use super::Client;

    /// A Platform double that records the privileged calls dispatch makes and
    /// returns canned values. Only the privileged methods are exercised; the pure
    /// ones panic if ever reached (dispatch must not touch them).
    #[derive(Default)]
    struct StubPlatform {
        started: std::sync::Mutex<Vec<(CoreEngine, u16)>>,
        stopped: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl Platform for StubPlatform {
        fn paths(&self) -> &BackendPaths {
            unimplemented!("pure method must stay GUI-side, never dispatched")
        }
        async fn boot_init(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn start_data_path(&self, opts: StartDataPath) -> anyhow::Result<()> {
            self.started
                .lock()
                .unwrap()
                .push((opts.engine, opts.socks_port));
            Ok(())
        }
        async fn stop_data_path(&self, _opts: StopDataPath) -> anyhow::Result<()> {
            self.stopped
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn service_state(&self) -> anyhow::Result<ServiceState> {
            Ok(ServiceState {
                state: RunState::Connecting,
                error: None,
                upload_bytes: 10,
                download_bytes: 20,
                uptime_sec: 5,
                engine: Some(CoreEngine::Xray),
            })
        }
        async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
            Ok(PlatformCapabilities {
                cores: InstalledCores {
                    xray: Some("x".into()),
                    singbox: None,
                },
                tun: true,
                bridge: "desktop".into(),
            })
        }
        fn core_path(&self, _engine: Engine) -> std::path::PathBuf {
            unimplemented!("pure method must stay GUI-side")
        }
        async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
            Ok(ProxyStatus {
                running: true,
                socks_port: 10808,
                http_port: 10809,
                force_port: 10810,
            })
        }
        fn tune_config(&self, _engine: Engine, _config: &mut Value) {
            unimplemented!("pure method must stay GUI-side")
        }
        async fn data_path_healthy(&self) -> Option<bool> {
            Some(true)
        }
    }

    /// End-to-end over a real unix socket: client request → server dispatch → stub
    /// Platform → reply, for every privileged variant.
    #[tokio::test]
    async fn round_trips_over_a_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("helper.sock");
        let sock_str = sock.to_string_lossy().into_owned();

        let platform: Arc<dyn Platform> = Arc::new(StubPlatform::default());
        let stub = platform.clone();
        let serve_path = sock_str.clone();
        tokio::spawn(async move {
            let _ = server::serve(platform, &serve_path, None).await;
        });

        // Wait for the listener to bind.
        let client = loop {
            if let Ok(c) = Client::connect(&sock_str).await {
                break c;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };

        assert_eq!(
            client.call(PrivRequest::Ping).await.unwrap(),
            PrivReply::Pong
        );
        assert_eq!(
            client.call(PrivRequest::BootInit).await.unwrap(),
            PrivReply::Ok
        );
        assert_eq!(
            client
                .call(PrivRequest::StartDataPath {
                    engine: CoreEngine::SingBox,
                    tun: kasumi_core::enums::TunEngine::SingboxTun,
                    tun_opts: kasumi_core::state::AdvancedSettings::default().tun_options(),
                    socks_port: 1080,
                    mode: kasumi_core::state::ProxyMode::Tun,
                })
                .await
                .unwrap(),
            PrivReply::Ok
        );
        match client.call(PrivRequest::ServiceState).await.unwrap() {
            PrivReply::State(s) => assert_eq!(s.download_bytes, 20),
            other => panic!("expected State, got {other:?}"),
        }
        match client.call(PrivRequest::ProxyStatus).await.unwrap() {
            PrivReply::Proxy { socks_port, .. } => assert_eq!(socks_port, 10808),
            other => panic!("expected Proxy, got {other:?}"),
        }
        assert_eq!(
            client.call(PrivRequest::DataPathHealthy).await.unwrap(),
            PrivReply::Healthy {
                healthy: Some(true)
            }
        );
        assert_eq!(
            client
                .call(PrivRequest::StopDataPath {
                    keep_service_state: false
                })
                .await
                .unwrap(),
            PrivReply::Ok
        );
        let _ = stub; // kept alive for the duration of the server task
    }
}
