//! Root side of privilege separation: serve [`proto`] requests against a real
//! [`Platform`] (the in-helper [`DesktopPlatform`]) over a unix socket.
//!
//! The helper runs as root and owns the data-path; the unprivileged GUI is the
//! only client. Each connection is a sequence of newline-delimited
//! [`PrivRequest`]s, each answered with exactly one [`PrivReply`]. Request handling
//! lives in [`Server::dispatch`] — a method on the owned serving state, so it can be
//! exercised without a socket.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;

use kasumi_backend::platform::{Platform, StartDataPath, StopDataPath, TestCore};

use super::proto::{PrivReply, PrivRequest};
use super::transport::{BoxRead, BoxWrite};

/// Generous vs the longest single test (~18 s): a core still registered this long
/// after spawn is an orphan, so the sweep can safely reap it.
const TEST_CORE_MAX_LIFETIME: Duration = Duration::from_secs(60);

/// The helper's serving state: the privileged [`Platform`] plus the test cores it
/// has spawned. One instance is shared across every connection, so a `KillTestCore`
/// reaches a core spawned on any connection and the orphan sweep shares the same
/// map. Owning this rather than a process global keeps [`Server::dispatch`] a
/// function of its inputs — each test builds its own `Server`.
pub struct Server {
    platform: Arc<dyn Platform>,
    /// Test cores spawned via `SpawnTestCore`, keyed by handle. The GUI releases each
    /// with `KillTestCore`; the orphan sweep backstops a GUI that vanishes mid-test.
    test_cores: AsyncMutex<HashMap<u64, Box<dyn TestCore>>>,
    /// Monotonic source of test-core handles.
    next_handle: AtomicU64,
}

impl Server {
    /// Wrap a platform for serving. `Arc` so connections and orphan-sweep tasks share
    /// the one registry.
    pub fn new(platform: Arc<dyn Platform>) -> Arc<Self> {
        Arc::new(Self {
            platform,
            test_cores: AsyncMutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
        })
    }

    /// Map one request to its reply by calling into the platform. Errors are folded
    /// into `PrivReply::Err` so a failing operation never drops the connection.
    pub async fn dispatch(self: &Arc<Self>, req: PrivRequest) -> PrivReply {
        match req {
            PrivRequest::Ping => PrivReply::Pong,
            PrivRequest::BootInit => to_reply(self.platform.boot_init().await),
            PrivRequest::StartDataPath { engine, socks_port } => to_reply(
                self.platform
                    .start_data_path(StartDataPath { engine, socks_port })
                    .await,
            ),
            PrivRequest::StopDataPath { keep_service_state } => to_reply(
                self.platform
                    .stop_data_path(StopDataPath { keep_service_state })
                    .await,
            ),
            PrivRequest::ServiceState => match self.platform.service_state().await {
                Ok(s) => PrivReply::State(s),
                Err(e) => PrivReply::Err {
                    message: e.to_string(),
                },
            },
            PrivRequest::ProxyStatus => match self.platform.proxy_status().await {
                Ok(p) => PrivReply::Proxy {
                    running: p.running,
                    socks_port: p.socks_port,
                    http_port: p.http_port,
                },
                Err(e) => PrivReply::Err {
                    message: e.to_string(),
                },
            },
            PrivRequest::DataPathHealthy => PrivReply::Healthy {
                healthy: self.platform.data_path_healthy().await,
            },
            PrivRequest::SpawnTestCore {
                engine,
                cfg_path,
                log_path,
            } => match self
                .platform
                .spawn_test_core(engine, Path::new(&cfg_path), Path::new(&log_path))
                .await
            {
                Ok(core) => {
                    let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
                    self.test_cores.lock().await.insert(handle, core);
                    // Backstop: reap the core if the GUI never sends KillTestCore.
                    let server = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(TEST_CORE_MAX_LIFETIME).await;
                        if let Some(mut c) = server.test_cores.lock().await.remove(&handle) {
                            log::warn!("orphan test core {handle} swept after timeout");
                            c.kill().await;
                        }
                    });
                    PrivReply::TestCoreSpawned { handle }
                }
                Err(e) => PrivReply::Err {
                    message: e.to_string(),
                },
            },
            PrivRequest::KillTestCore { handle } => {
                if let Some(mut c) = self.test_cores.lock().await.remove(&handle) {
                    c.kill().await;
                }
                PrivReply::Ok
            }
        }
    }
}

/// `Ok(())` → `PrivReply::Ok`, otherwise the stringified error.
fn to_reply(r: anyhow::Result<()>) -> PrivReply {
    match r {
        Ok(()) => PrivReply::Ok,
        Err(e) => PrivReply::Err {
            message: e.to_string(),
        },
    }
}

/// Bind `socket_path` and serve requests against `platform` until the process
/// exits. Removes any stale socket first. Connections are served concurrently;
/// within a connection requests are answered in order.
///
/// `owner_uid` is the unprivileged user that may drive the helper: the socket is
/// `chown`ed to it and locked to `0600`, so that user can connect but no other
/// local account can reach the root data-path. `None` leaves the socket owned by
/// the running user (tests, or a same-user run).
#[cfg(unix)]
pub async fn serve(
    platform: Arc<dyn Platform>,
    socket_path: &str,
    owner_uid: Option<u32>,
) -> anyhow::Result<()> {
    use anyhow::Context;
    use tokio::net::UnixListener;

    let _ = tokio::fs::remove_file(socket_path).await;
    // Narrow the bind→chmod window: create the socket 0600 from the start (root's
    // umask is otherwise 022, leaving it briefly group/other-readable) so no other
    // account can connect even for an instant.
    let prev_umask = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind privilege-helper socket {socket_path}"));
    unsafe { libc::umask(prev_umask) };
    let listener = listener?;
    restrict_socket(socket_path, owner_uid)
        .with_context(|| format!("restrict privilege-helper socket {socket_path}"))?;
    let server = Server::new(platform);
    loop {
        let (stream, _addr) = listener.accept().await?;
        let (read, write) = tokio::io::split(stream);
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(server, Box::new(read), Box::new(write)).await {
                log::warn!("connection ended: {e}");
            }
        });
    }
}

/// Lock the freshly-bound socket to the owning user: `0600` so only its owner can
/// connect, and `chown` to `owner_uid` so that owner is the unprivileged GUI user
/// rather than root (which bound it).
#[cfg(unix)]
fn restrict_socket(socket_path: &str, owner_uid: Option<u32>) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    if let Some(uid) = owner_uid {
        // Leave the gid untouched — 0600 already excludes group/other, so the
        // user's (unknown here) primary group is immaterial.
        std::os::unix::fs::chown(socket_path, Some(uid), None)?;
    }
    Ok(())
}

/// Read requests line by line off one connection and write one reply per request.
/// Transport-neutral: the caller supplies the already-split halves (a unix socket
/// on Linux, a named pipe on Windows).
pub(crate) async fn serve_conn(
    server: Arc<Server>,
    read: BoxRead,
    mut write: BoxWrite,
) -> anyhow::Result<()> {
    let mut lines = BufReader::new(read).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<PrivRequest>(&line) {
            Ok(req) => {
                log::debug!("request: {req:?}");
                server.dispatch(req).await
            }
            Err(e) => {
                log::warn!("malformed request: {e}");
                PrivReply::Err {
                    message: format!("malformed request: {e}"),
                }
            }
        };
        if let PrivReply::Err { message } = &reply {
            log::warn!("reply error: {message}");
        }
        let mut buf = serde_json::to_vec(&reply)?;
        buf.push(b'\n');
        write.write_all(&buf).await?;
        write.flush().await?;
    }
    Ok(())
}
