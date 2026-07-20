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
    /// The unprivileged GUI user runtime files created by the privileged data-path
    /// are handed back to (see [`Server::hand_files_to_owner`]). `None` for a
    /// same-user run (tests, or a caps-only wrapper already running as the user).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    owner_uid: Option<u32>,
}

impl Server {
    /// Wrap a platform for serving. `Arc` so connections and orphan-sweep tasks share
    /// the one registry. `owner_uid` is the unprivileged user helper-created files are
    /// handed to; `None` where the helper runs as that user already.
    pub fn new(platform: Arc<dyn Platform>, owner_uid: Option<u32>) -> Arc<Self> {
        Arc::new(Self {
            platform,
            test_cores: AsyncMutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            owner_uid,
        })
    }

    /// Map one request to its reply by calling into the platform. Errors are folded
    /// into `PrivReply::Err` so a failing operation never drops the connection.
    pub async fn dispatch(self: &Arc<Self>, req: PrivRequest) -> PrivReply {
        // Which helper-created files this request leaves behind, resolved before `req`
        // is consumed so they can be handed to the GUI owner once it is handled.
        #[cfg(target_os = "linux")]
        let handoff = Handoff::for_request(&req);
        let reply = match req {
            PrivRequest::Ping => PrivReply::Pong,
            PrivRequest::BootInit => to_reply(self.platform.boot_init().await),
            PrivRequest::StartDataPath {
                engine,
                tun,
                tun_opts,
                socks_port,
                mode,
            } => to_reply(
                self.platform
                    .start_data_path(StartDataPath {
                        engine,
                        tun,
                        tun_opts,
                        socks_port,
                        mode,
                    })
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
        };
        #[cfg(target_os = "linux")]
        self.hand_files_to_owner(handoff).await;
        reply
    }
}

/// The helper-created files one request leaves behind, so [`Server::hand_files_to_owner`]
/// can chown exactly those to the GUI user after the request is handled.
#[cfg(target_os = "linux")]
enum Handoff {
    /// Nothing helper-owned was written.
    None,
    /// The ephemeral run-dir state, engine configs and core logs of a data-path
    /// start/stop (the fixed [`DesktopPaths::helper_owned_files`] list).
    RuntimeFiles,
    /// A single test core's log, at the GUI-chosen path carried in the request (its
    /// port is dynamic, so it can't be part of the fixed list).
    TestLog(std::path::PathBuf),
}

#[cfg(target_os = "linux")]
impl Handoff {
    fn for_request(req: &PrivRequest) -> Self {
        match req {
            PrivRequest::StartDataPath { .. } | PrivRequest::StopDataPath { .. } => {
                Handoff::RuntimeFiles
            }
            PrivRequest::SpawnTestCore { log_path, .. } => {
                Handoff::TestLog(std::path::PathBuf::from(log_path))
            }
            _ => Handoff::None,
        }
    }
}

/// The uid to hand files to: the owner, unless it is our own euid (a caps-only
/// wrapper runs as the GUI user already, so chowning would be a needless no-op).
#[cfg(target_os = "linux")]
fn hand_off_target(owner_uid: Option<u32>, euid: u32) -> Option<u32> {
    owner_uid.filter(|&uid| uid != euid)
}

#[cfg(target_os = "linux")]
impl Server {
    /// Chown the files a just-handled request left behind to the GUI owner, so an
    /// unprivileged in-process data-path owner can later read/replace them without
    /// EACCES. Missing files and per-file errors are ignored (a file the run didn't
    /// create is normal); only the exact known paths are touched — the regular-file
    /// list plus the app-owned run-dir inodes (create/unlink rights live on the
    /// containing directory, not the files) — never anything recursive.
    async fn hand_files_to_owner(&self, handoff: Handoff) {
        let Some(uid) = hand_off_target(self.owner_uid, unsafe { libc::geteuid() }) else {
            return;
        };
        let files = match handoff {
            Handoff::None => return,
            Handoff::TestLog(path) => vec![path],
            Handoff::RuntimeFiles => match crate::desktop::paths::DesktopPaths::resolve() {
                Ok(paths) => {
                    let mut all = paths.helper_owned_files();
                    all.extend(paths.helper_owned_dirs());
                    all
                }
                Err(e) => {
                    log::warn!("could not resolve paths to hand files to the owner: {e}");
                    return;
                }
            },
        };
        for path in files {
            let _ = std::os::unix::fs::chown(&path, Some(uid), None);
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
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind privilege-helper socket {socket_path}"))?;
    // Lock the socket to 0600 right after bind rather than toggling the process-global
    // umask around it — a mask that any concurrent file creation on another thread
    // would inherit. The bind→restrict window is harmless: connecting to a unix socket
    // needs write permission, which the helper's inherited (pkexec) 022 umask denies
    // group/other, and `restrict_socket` pins 0600 immediately regardless.
    restrict_socket(socket_path, owner_uid)
        .with_context(|| format!("restrict privilege-helper socket {socket_path}"))?;
    let server = Server::new(platform, owner_uid);
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn hand_off_skips_a_same_user_run() {
        // No owner set, or an owner that is our own euid: nothing to hand off.
        assert_eq!(hand_off_target(None, 1000), None);
        assert_eq!(hand_off_target(Some(1000), 1000), None);
        // A distinct unprivileged owner while running privileged: hand off to it.
        assert_eq!(hand_off_target(Some(1000), 0), Some(1000));
    }

    #[test]
    fn handoff_classifies_file_creating_requests() {
        assert!(matches!(
            Handoff::for_request(&PrivRequest::StopDataPath {
                keep_service_state: false,
            }),
            Handoff::RuntimeFiles
        ));
        let log = "/run/kasumi/test-43210.log";
        assert!(matches!(
            Handoff::for_request(&PrivRequest::SpawnTestCore {
                engine: kasumi_backend::platform::Engine::Xray,
                cfg_path: "/run/kasumi/test-43210.json".into(),
                log_path: log.into(),
            }),
            Handoff::TestLog(p) if p == std::path::Path::new(log)
        ));
        assert!(matches!(
            Handoff::for_request(&PrivRequest::Ping),
            Handoff::None
        ));
    }
}
