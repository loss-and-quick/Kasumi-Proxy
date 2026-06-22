//! The privileged data-path helper, spawned as root by the unprivileged GUI.
//! Linux-only; see `desktop::privhelper`.

fn main() {
    #[cfg(target_os = "linux")]
    kasumi_desktop_lib::desktop::privhelper::run_helper();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("kasumi-helper is Linux-only");
        std::process::exit(1);
    }
}
