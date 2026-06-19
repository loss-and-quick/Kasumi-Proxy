//! `kasumi-proxy` — headless daemon binary (KSU/Magisk/APatch module + any headless
//! host). `daemon` runs the long-running server; any other argv is a one-shot CLI
//! command. See [`kasumi_daemon::run`].

#[tokio::main]
async fn main() {
    kasumi_daemon::run::run_entry().await;
}
