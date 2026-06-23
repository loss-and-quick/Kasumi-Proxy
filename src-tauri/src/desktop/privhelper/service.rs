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

use std::ffi::{c_void, OsStr, OsString};
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

use super::server::serve_conn;
use crate::desktop::paths::{
    ARG_BIN_DIR, ARG_DATADIR, ARG_RUNDIR, ENV_BIN_DIR, ENV_DATADIR, ENV_RUNDIR,
};
use crate::desktop::DesktopPlatform;

/// SCM identifier; shared with the GUI client ([`super::connect`]).
pub(crate) const SERVICE_NAME: &str = "KasumiProxyHelper";
const SERVICE_DISPLAY: &str = "Kasumi Proxy Helper";
/// The pipe the service binds and the GUI dials. Fixed name, locked by SD to the
/// interactive user; multi-session (RDP) co-use is out of scope.
pub(crate) const PIPE_NAME: &str = r"\\.\pipe\kasumi-proxy-helper";

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
            std::env::set_var(env, val);
        }
    }
}

fn run_service(arguments: Vec<OsString>) -> anyhow::Result<()> {
    apply_path_args(&arguments);

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
        serve_pipe(platform, shutdown).await
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

/// Serve the GUI over the named pipe until the service is stopped. One client (the
/// GUI's single held-open connection) at a time; when it disconnects the data-path
/// is torn down, mirroring the Linux helper exiting with the GUI.
async fn serve_pipe(platform: Arc<dyn Platform>, shutdown: Arc<Notify>) -> anyhow::Result<()> {
    let security = PipeSecurity::new()?;
    let mut first = true;
    loop {
        let server = bind_pipe(PIPE_NAME, &security, first)?;
        first = false;

        tokio::select! {
            res = server.connect() => res.context("await pipe client")?,
            _ = shutdown.notified() => break,
        }

        let (read, write) = tokio::io::split(server);
        tokio::select! {
            r = serve_conn(platform.clone(), Box::new(read), Box::new(write)) => {
                if let Err(e) = r {
                    log::warn!("connection ended: {e}");
                }
            }
            _ = shutdown.notified() => {
                teardown(&platform).await;
                break;
            }
        }
        // GUI gone → tear the data-path down so a crashed GUI can't leave it up.
        teardown(&platform).await;
    }
    teardown(&platform).await;
    Ok(())
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

    let (read, write) = tokio::io::split(server);
    if let Err(e) = serve_conn(platform.clone(), Box::new(read), Box::new(write)).await {
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
    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            let _ = service.stop();
        }
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
