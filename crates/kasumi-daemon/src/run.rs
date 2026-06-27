//! Binary entry: dispatch on argv. `kasumi-proxy daemon` runs the long-running
//! daemon (boot init → Service → HTTP/WS server); any other argv is a one-shot CLI
//! command the module's shell scripts use (e.g. `rotateLogs`).

use std::sync::Arc;

use kasumi_backend::fs::write_text;
use kasumi_backend::platform::{Platform, StopDataPath};
use kasumi_backend::proc::{kill_if_running, read_pidfile};
use kasumi_backend::{dispatch, Command, Response, Service};

use crate::android::paths::DAEMON_PIDFILE;
use crate::android::AndroidPlatform;
use crate::server;

pub async fn run_entry() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let platform: Arc<dyn Platform> = Arc::new(AndroidPlatform::new());
    match args.first().map(String::as_str) {
        Some("daemon") => run_daemon(platform).await,
        // Process-level stop used by uninstall.sh: kill the running daemon (so its
        // watchdog can't restart the proxy) and tear the data-path down. Not a
        // `Command` — lifecycle verbs are rejected on the CLI path on purpose.
        Some("stop") => run_stop(platform).await,
        _ => run_cli(platform, &args).await,
    }
}

async fn run_daemon(platform: Arc<dyn Platform>) {
    // Operational logging to stderr, which service.sh redirects into daemon.log.
    // Default to info; override at runtime with RUST_LOG (e.g. RUST_LOG=debug).
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .target(env_logger::Target::Stderr)
        .init();
    log::info!("kasumi-proxy daemon starting");

    // One-time boot setup (route tables, sysctl locks, seed lifecycle state).
    // boot_init creates RUN_DIR, so the pidfile write below has somewhere to land.
    if let Err(e) = platform.boot_init().await {
        eprintln!("kasumi-proxy: boot init failed: {e}");
    }

    // Record our own pid so `kasumi-proxy stop` (uninstall.sh) can find and
    // terminate this process, which runs the graceful teardown below.
    if let Err(e) = write_text(DAEMON_PIDFILE, &std::process::id().to_string()).await {
        eprintln!("kasumi-proxy: could not write {DAEMON_PIDFILE}: {e}");
    }

    let service = Service::new(platform.clone()).await;
    service.spawn_background();

    // Graceful shutdown: tear down the data-path (core + tun + routing) before
    // exiting so nothing lingers. stop_data_path is idempotent.
    let shutdown = platform.clone();
    tokio::spawn(async move {
        wait_for_signal().await;
        let _ = shutdown.stop_data_path(StopDataPath::default()).await;
        std::process::exit(0);
    });

    if let Err(e) = server::serve(service).await {
        eprintln!("kasumi-proxy: server error: {e}");
        std::process::exit(1);
    }
}

/// Stop a running daemon and leave a clean system. Used by `uninstall.sh` before
/// it drops `/data/adb/kasumi-proxy`. First terminate the daemon process (graceful
/// SIGTERM → SIGKILL, dropping its pidfile) so its watchdog can't bring the proxy
/// back up; then run the idempotent data-path teardown to sweep any TUN/iptables/
/// routes left behind even if the daemon was already gone.
async fn run_stop(platform: Arc<dyn Platform>) {
    let pid = read_pidfile(DAEMON_PIDFILE).await;
    kill_if_running(pid, None, DAEMON_PIDFILE, true).await;
    let _ = platform.stop_data_path(StopDataPath::default()).await;
    print_response(Response::Ok);
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut intr = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = intr.recv() => {}
    }
}

/// Map a one-shot CLI verb to a typed command. Only the verbs the module's shell
/// scripts invoke are wired; lifecycle goes through the daemon, not the CLI.
fn parse_cli(args: &[String]) -> Option<Command> {
    Some(match args.first()?.as_str() {
        "readState" => Command::ReadState,
        "status" => Command::Status,
        "wsInfo" => Command::WsInfo,
        "capabilities" => Command::Capabilities,
        "listAssets" => Command::ListAssets,
        "listApps" => Command::ListApps,
        "clearLogs" => Command::ClearLogs,
        "rotateLogs" => Command::RotateLogs { max_kb: None },
        "log" => Command::Log {
            target: None,
            lines: None,
        },
        _ => return None,
    })
}

async fn run_cli(platform: Arc<dyn Platform>, args: &[String]) {
    let Some(cmd) = parse_cli(args) else {
        let verb = args.first().map(String::as_str).unwrap_or("");
        print_error(&format!("unknown command: {verb}"));
        std::process::exit(1);
    };
    match dispatch(&*platform, cmd).await {
        Ok(resp) => print_response(resp),
        Err(e) => {
            print_error(&e.0);
            std::process::exit(1);
        }
    }
}

fn print_response(resp: Response) {
    match resp {
        Response::Text(s) => println!("{s}"),
        Response::Ok => println!("{}", serde_json::json!({ "ok": true })),
        other => println!("{}", serde_json::to_string(&other).unwrap_or_default()),
    }
}

fn print_error(message: &str) {
    println!("{}", serde_json::json!({ "ok": false, "error": message }));
}
