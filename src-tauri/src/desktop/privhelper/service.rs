//! Windows side of privilege separation: a LocalSystem service that owns the
//! data-path, the analogue of the Linux root helper.
//!
//! The unprivileged GUI talks to it over a named pipe secured to the logged-on user,
//! reusing the OS-neutral [`super::server::serve_conn`] / [`super::proto`] from the
//! Linux path. The service is registered once at install (elevated), demand-started
//! by the GUI with the GUI's resolved paths as launch arguments — exactly how the
//! Linux helper receives them across pkexec — and stops the data-path when the GUI
//! disconnects, so a crashed GUI never leaves the tunnel up. State travels back in
//! replies, never through SYSTEM-owned files.
//!
//! Portable builds skip the service entirely: the GUI runs the helper transiently
//! under UAC ([`run_transient`]) on each launch, serving one session over a
//! per-GUI pipe and exiting with the GUI — the exact mirror of the Linux pkexec
//! helper, leaving nothing installed.

use std::ffi::{OsStr, OsString, c_void};
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::Notify;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use kasumi_backend::platform::{Platform, StopDataPath};

use super::server::{Server, serve_conn};
use crate::desktop::DesktopPlatform;
use crate::desktop::paths::{
    ARG_BIN_DIR, ARG_DATADIR, ARG_RUNDIR, ENV_BIN_DIR, ENV_DATADIR, ENV_RUNDIR,
};

/// SCM identifier; shared with the GUI client ([`super::connect`]).
pub(crate) const SERVICE_NAME: &str = "KasumiProxyHelper";
const SERVICE_DISPLAY: &str = "Kasumi Proxy Helper";
/// The pipe the service binds and the GUI dials. Fixed name, locked by SD to the
/// interactive users; the service serves only the session that started it (see
/// [`super::session`]).
pub(crate) const PIPE_NAME: &str = r"\\.\pipe\kasumi-proxy-helper";
/// Start argument carrying the Windows session of the GUI that starts the service.
pub(crate) const ARG_SESSION: &str = "--session";

/// `s` as a NUL-terminated UTF-16 buffer for the Win32 `*W` APIs. Shared with the
/// GUI-side [`super::connect`].
pub(crate) fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// ----- service runtime (SCM-launched, `kasumi-helper --service`) -----

define_windows_service!(ffi_service_main, service_main);

/// Hand control to the SCM dispatcher; returns only once the service stops.
pub fn run_dispatcher() -> ! {
    if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        eprintln!("kasumi-helper: service dispatcher failed: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        log::error!("service error: {e}");
    }
}

/// Portable mode: serve one GUI session over the per-GUI pipe given by `--pipe`,
/// then exit. Spawned elevated by the GUI (no SCM), so it parses the same path args
/// off its own command line. Never returns on success.
pub fn run_transient() -> ! {
    if let Err(e) = run_transient_inner() {
        eprintln!("kasumi-helper: {e}");
        log::error!("transient helper exited with error: {e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn run_transient_inner() -> anyhow::Result<()> {
    let args: Vec<OsString> = std::env::args_os().collect();
    apply_path_args(&args);
    let pipe = arg_value(&args, "--pipe").context("--serve needs --pipe")?;
    let pipe = pipe
        .to_str()
        .context("pipe name is not valid UTF-16")?
        .to_owned();

    tokio::runtime::Runtime::new()?.block_on(async {
        let platform: Arc<dyn Platform> = Arc::new(DesktopPlatform::new()?);
        super::hlog::init(&platform.paths().run_dir);
        log::info!("transient helper starting: pipe={pipe}");
        tokio::fs::create_dir_all(&platform.paths().run_dir).await?;
        serve_transient(platform, &pipe).await
    })
}

/// The value following `key` in `args`, if present.
fn arg_value(args: &[OsString], key: &str) -> Option<OsString> {
    args.windows(2)
        .find(|w| w[0].to_str() == Some(key))
        .map(|w| w[1].clone())
}

/// Pull `--datadir/--rundir/--bin-dir` out of the SCM start arguments and export
/// them so `DesktopPaths::resolve` (run as SYSTEM) lands on the GUI user's dirs —
/// the Windows analogue of the args the Linux helper gets from pkexec.
fn apply_path_args(arguments: &[OsString]) {
    let mut it = arguments.iter().skip(1);
    while let Some(key) = it.next() {
        let env = match key.to_str() {
            Some(ARG_DATADIR) => ENV_DATADIR,
            Some(ARG_RUNDIR) => ENV_RUNDIR,
            Some(ARG_BIN_DIR) => ENV_BIN_DIR,
            _ => continue,
        };
        if let Some(val) = it.next() {
            // SAFETY: `apply_path_args` runs once on the SCM ServiceMain thread
            // during service startup, before the data-path runtime and its worker
            // threads exist — no concurrent reader of the environment.
            unsafe {
                std::env::set_var(env, val);
            }
        }
    }
}

fn run_service(arguments: Vec<OsString>) -> anyhow::Result<()> {
    apply_path_args(&arguments);
    let owner = arg_value(&arguments, ARG_SESSION)
        .and_then(|s| s.to_str().and_then(|s| s.parse::<u32>().ok()));

    let shutdown = Arc::new(Notify::new());
    let on_control = {
        let shutdown = shutdown.clone();
        move |control| match control {
            ServiceControl::Stop => {
                shutdown.notify_one();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, on_control)
        .context("register service control handler")?;

    let report = |state, accept| {
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    };

    report(ServiceState::Running, ServiceControlAccept::STOP)?;
    let result = tokio::runtime::Runtime::new()?.block_on(async {
        let platform: Arc<dyn Platform> = Arc::new(DesktopPlatform::new()?);
        super::hlog::init(&platform.paths().run_dir);
        log::info!("service starting");
        // The run dir holds the helper-owned data-path state; create it as SYSTEM.
        tokio::fs::create_dir_all(&platform.paths().run_dir).await?;
        serve_pipe(platform, shutdown, owner, PIPE_NAME).await
    });
    report(ServiceState::Stopped, ServiceControlAccept::empty())?;
    result
}

/// Create one instance of the secured named pipe `name`. `first` asserts no other
/// process already owns the name; set it on the first instance the helper binds.
fn bind_pipe(
    name: &str,
    security: &PipeSecurity,
    first: bool,
) -> anyhow::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(name, security.attrs_ptr())
    }
    .context("create named pipe instance")
}

/// Serve the GUI over the named pipe `name` until the service is stopped. One client (the
/// GUI's single held-open connection) at a time; when it disconnects the data-path
/// is torn down, mirroring the Linux helper exiting with the GUI.
///
/// Pipe names are machine-wide, so a GUI in another Windows session reaches the same
/// pipe. With `owner` (the session of the GUI that started the service and whose
/// paths it runs with) only that session is served, any other client is told who
/// owns the data-path, and the service exits once its GUI is gone, so the next GUI
/// to start it, from any session, brings its own paths. Without `owner` (started by
/// an older GUI) it serves any session, one at a time, and stays up, as before.
async fn serve_pipe(
    platform: Arc<dyn Platform>,
    shutdown: Arc<Notify>,
    owner: Option<u32>,
    name: &str,
) -> anyhow::Result<()> {
    let security = PipeSecurity::new()?;
    let srv = Server::new(platform.clone(), None);
    let mut first = true;
    // The connection being served, and its session.
    let mut active: Option<(tokio::task::JoinHandle<()>, Option<u32>)> = None;
    // A GUI that started the service but died before connecting must not leave it
    // owned forever.
    let first_client = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(first_client);
    let mut served_any = false;
    loop {
        let server = bind_pipe(name, &security, first)?;
        first = false;

        tokio::select! {
            res = server.connect() => res.context("await pipe client")?,
            _ = shutdown.notified() => break,
            _ = async { active.as_mut().map(|(task, _)| task).unwrap().await }, if active.is_some() => {
                active = None;
                // GUI gone → tear the data-path down so a crashed GUI can't leave it up.
                teardown(&platform).await;
                if owner.is_some() {
                    break;
                }
                continue;
            }
            _ = &mut first_client, if owner.is_some() && !served_any => {
                log::warn!("no GUI connected within 60s; exiting");
                break;
            }
        }

        let client = client_session(&server);
        let serving = active.as_ref().map(|(_, session)| *session);
        match super::session::admit(owner, client, serving) {
            super::session::Admission::Serve => {
                served_any = true;
                let (read, write) = tokio::io::split(server);
                let task = tokio::spawn(serve_conn(srv.clone(), Box::new(read), Box::new(write)));
                let task = tokio::spawn(async move {
                    if let Ok(Err(e)) = task.await {
                        log::warn!("connection ended: {e}");
                    }
                });
                active = Some((task, client));
            }
            super::session::Admission::Refuse { owner } => {
                log::warn!("refusing a GUI in session {client:?}: the data-path is held");
                tokio::spawn(refuse(server, owner));
            }
        }
    }
    if let Some((task, _)) = active {
        task.abort();
    }
    teardown(&platform).await;
    Ok(())
}

/// Windows session of the process at the other end of `pipe`.
/// <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientsessionid>
fn client_session(pipe: &tokio::net::windows::named_pipe::NamedPipeServer) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientSessionId;
    let mut session = 0u32;
    // SAFETY: the handle is a connected pipe instance owned by `pipe`.
    let ok = unsafe { GetNamedPipeClientSessionId(pipe.as_raw_handle(), &mut session) };
    (ok != 0).then_some(session)
}

/// The Windows session this process runs in.
/// <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid>
pub(crate) fn own_session() -> Option<u32> {
    use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut session = 0u32;
    // SAFETY: plain out-parameter call.
    let ok = unsafe { ProcessIdToSessionId(std::process::id(), &mut session) };
    (ok != 0).then_some(session)
}

/// Answer the refused GUI's first request with who owns the data-path, then hang up.
async fn refuse(pipe: tokio::net::windows::named_pipe::NamedPipeServer, owner: Option<u32>) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let (read, mut write) = tokio::io::split(pipe);
    let mut lines = BufReader::new(read).lines();
    let Ok(Ok(Some(_))) = tokio::time::timeout(Duration::from_secs(5), lines.next_line()).await
    else {
        return;
    };
    if let Ok(mut line) = serde_json::to_vec(&super::proto::PrivReply::OtherSession { owner }) {
        line.push(b'\n');
        let _ = write.write_all(&line).await;
        let _ = write.flush().await;
    }
}

async fn teardown(platform: &Arc<dyn Platform>) {
    let _ = platform
        .stop_data_path(StopDataPath {
            keep_service_state: false,
        })
        .await;
}

/// Portable lifetime: bind `pipe_name`, serve the GUI's single connection, then tear
/// the data-path down and return so the process exits. No loop, no SCM — the helper
/// lives exactly as long as the GUI, like the Linux pkexec helper. The initial accept
/// is bounded so a GUI that crashes before dialing can't leave us elevated forever.
async fn serve_transient(platform: Arc<dyn Platform>, pipe_name: &str) -> anyhow::Result<()> {
    let security = PipeSecurity::new()?;
    let server = bind_pipe(pipe_name, &security, true)?;

    tokio::select! {
        res = server.connect() => res.context("await pipe client")?,
        _ = tokio::time::sleep(Duration::from_secs(60)) => {
            log::warn!("no GUI connected within 60s; exiting");
            return Ok(());
        }
    }
    log::info!("GUI connected; serving data-path");

    let srv = Server::new(platform.clone(), None);
    let (read, write) = tokio::io::split(server);
    if let Err(e) = serve_conn(srv, Box::new(read), Box::new(write)).await {
        log::warn!("connection ended: {e}");
    }
    teardown(&platform).await;
    Ok(())
}

/// A security descriptor admitting only SYSTEM, Administrators (full) and the
/// interactive user (read/write) to the pipe — the Windows analogue of the Linux
/// socket's `0600` + `chown`. Holds the `LocalAlloc`'d descriptor for its lifetime.
struct PipeSecurity {
    descriptor: *mut c_void,
    attrs: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    fn new() -> anyhow::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

        let sddl = wide("D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFW;;;IU)");
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error()).context("build pipe security descriptor");
        }
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok(Self { descriptor, attrs })
    }

    /// Pointer to the `SECURITY_ATTRIBUTES` for `create_with_security_attributes_raw`
    /// (it reads, never writes, the struct).
    fn attrs_ptr(&self) -> *mut c_void {
        &self.attrs as *const _ as *mut c_void
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.descriptor) };
    }
}

// ----- install / uninstall (`kasumi-helper --install|--uninstall`, elevated) -----

/// Register the demand-start service (idempotent) and grant the logged-on user
/// permission to start/stop it, so later launches need no elevation. Run elevated.
pub fn install() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("open SCM")?;

    if manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .is_ok()
    {
        // Already present (e.g. reinstall); just re-assert the user-start DACL.
        return grant_user_control();
    }

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe().context("locate helper exe")?,
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG)
        .context("create service")?;
    let _ = service.set_description(
        "Owns the Kasumi Proxy data-path (tun + routing) so the GUI runs unprivileged.",
    );
    grant_user_control()
}

/// Stop and remove the service. Idempotent — a missing service is success.
pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("open SCM")?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    if let Ok(status) = service.query_status()
        && status.current_state != ServiceState::Stopped
    {
        let _ = service.stop();
    }
    service.delete().context("delete service")?;
    Ok(())
}

/// Replace the service DACL so the logged-on user can start/stop/query it (SYSTEM
/// and Administrators keep full control). Done via `sc sdset` rather than raw
/// `SetServiceObjectSecurity` — the service crate exposes no DACL setter, and the
/// full-SDDL form is auditable. Runs in the elevated install context.
fn grant_user_control() -> anyhow::Result<()> {
    const SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPLORC;;;AU)";
    let status = std::process::Command::new("sc.exe")
        .args(["sdset", SERVICE_NAME, SDDL])
        .status()
        .context("run sc sdset")?;
    if !status.success() {
        anyhow::bail!("sc sdset failed with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use kasumi_backend::net::ProxyStatus;
    use kasumi_backend::platform::{BackendPaths, Engine, PlatformCapabilities, StopDataPath};
    use kasumi_core::contract::ServiceState as DataPathState;
    use kasumi_core::data_path_plan::{DataPathPlan, HostTraits};

    use super::super::client::Client;
    use super::super::proto::{PROTOCOL_VERSION, PrivReply, PrivRequest};
    use super::*;

    /// Counts teardowns; nothing else is reached from the pipe loop.
    #[derive(Default)]
    struct StubPlatform {
        stops: AtomicUsize,
    }

    #[async_trait]
    impl Platform for StubPlatform {
        fn paths(&self) -> &BackendPaths {
            unimplemented!()
        }
        fn host_traits(&self) -> HostTraits {
            unimplemented!()
        }
        async fn start_data_path(&self, _plan: &DataPathPlan) -> anyhow::Result<()> {
            Ok(())
        }
        async fn stop_data_path(&self, _opts: StopDataPath) -> anyhow::Result<()> {
            self.stops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn service_state(&self) -> anyhow::Result<DataPathState> {
            unimplemented!()
        }
        async fn capabilities(&self) -> anyhow::Result<PlatformCapabilities> {
            unimplemented!()
        }
        fn core_path(&self, _engine: Engine) -> std::path::PathBuf {
            unimplemented!()
        }
        async fn proxy_status(&self) -> anyhow::Result<ProxyStatus> {
            unimplemented!()
        }
    }

    /// Pipe names are machine-wide, so each test binds its own: apart from an
    /// installed service's pipe, and from the other test's, whose instances outlive
    /// its loop until the runtime reaps their cancelled accepts.
    fn pipe_name(test: &str) -> String {
        format!(
            r"\\.\pipe\kasumi-proxy-helper-test-{}-{test}",
            std::process::id()
        )
    }

    async fn connect(name: &str) -> Client {
        let mut last = None;
        for _ in 0..100 {
            match Client::connect(name).await {
                Ok(c) => return c,
                Err(e) => last = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("pipe never came up: {last:?}");
    }

    /// Run the service loop alongside `guis` until both are done. A loop that fails
    /// (say, to bind its pipe) fails the test at once.
    async fn run(
        service: impl Future<Output = anyhow::Result<()>>,
        guis: impl Future<Output = ()>,
    ) {
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::try_join!(service, async {
                guis.await;
                Ok(())
            })
        })
        .await
        .expect("the service did not stop")
        .unwrap();
    }

    #[tokio::test]
    async fn serves_its_gui_and_refuses_a_second_one() {
        let name = pipe_name("owner");
        let stub = Arc::new(StubPlatform::default());
        let platform: Arc<dyn Platform> = stub.clone();
        let mine = own_session().expect("session of the test process");
        let guis = async {
            let owner = connect(&name).await;
            assert_eq!(
                owner.call_raw(PrivRequest::Ping).await.unwrap(),
                PrivReply::Pong {
                    protocol: Some(PROTOCOL_VERSION),
                }
            );
            // A second GUI, here from the same session, is told the data-path is held.
            let second = connect(&name).await;
            assert_eq!(
                second.call_raw(PrivRequest::Ping).await.unwrap(),
                PrivReply::OtherSession { owner: Some(mine) }
            );
            // The owner leaving tears the data-path down and ends the service.
            drop(owner);
        };
        let shutdown = Arc::new(Notify::new());
        run(serve_pipe(platform, shutdown, Some(mine), &name), guis).await;
        assert!(stub.stops.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn refuses_a_gui_from_another_session() {
        let name = pipe_name("other");
        let platform: Arc<dyn Platform> = Arc::new(StubPlatform::default());
        let other = own_session().expect("session of the test process") + 1;
        let stop = Arc::new(Notify::new());
        let guis = async {
            let gui = connect(&name).await;
            assert_eq!(
                gui.call_raw(PrivRequest::Ping).await.unwrap(),
                PrivReply::OtherSession { owner: Some(other) }
            );
            stop.notify_one();
        };
        run(serve_pipe(platform, stop.clone(), Some(other), &name), guis).await;
    }
}
