//! The privileged data-path helper. On Linux it is spawned as root by the GUI and
//! serves the data-path directly. On Windows it is the LocalSystem service: run
//! `--install`/`--uninstall` (elevated) to register it, `--service` when the SCM
//! launches it. See `desktop::privhelper`.

fn main() {
    #[cfg(target_os = "linux")]
    kasumi_desktop_lib::desktop::privhelper::run_helper();

    #[cfg(target_os = "windows")]
    {
        use kasumi_desktop_lib::desktop::privhelper::service;
        let outcome = match std::env::args().nth(1).as_deref() {
            Some("--install") => service::install(),
            Some("--uninstall") => service::uninstall(),
            Some("--service") => service::run_dispatcher(),
            _ => {
                eprintln!("usage: kasumi-helper --install | --uninstall | --service");
                std::process::exit(2);
            }
        };
        if let Err(e) = outcome {
            eprintln!("kasumi-helper: {e}");
            std::process::exit(1);
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        eprintln!("kasumi-helper is Linux/Windows-only");
        std::process::exit(1);
    }
}
