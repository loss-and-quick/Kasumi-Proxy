//! "Launch on login" as an XDG autostart entry (`~/.config/autostart/*.desktop`).
//!
//! The entry runs the launcher by name — `kasumi-desktop --autostart` — not the
//! path of the running binary. On NixOS that
//! path is the unwrapped `.kasumi-desktop-wrapped` in the store: started directly it
//! misses the wrapper's GTK env, `KASUMI_BIN_DIR` and `ip` on PATH, and a rebuild +
//! GC leaves it pointing at nothing. The bare name resolves through the session
//! PATH to the wrapper (`/run/current-system/sw/bin`) or to `/usr/bin` for deb/rpm.
//! An AppImage has no PATH entry, so it is run by its own `$APPIMAGE` path.

use std::io;
use std::path::{Path, PathBuf};

/// Same basename as the launcher entry the packages install.
const ENTRY: &str = "kasumi-proxy.desktop";
/// The entry tauri-plugin-autostart wrote (named after `productName`), with the
/// absolute exe path; replaced by [`ENTRY`] on the next start.
const LEGACY_ENTRY: &str = "Kasumi Proxy.desktop";
const BIN: &str = "kasumi-desktop";
use crate::AUTOSTART_ARG;

/// What the exec choice depends on, read once from the process env.
struct Launch {
    appimage: Option<PathBuf>,
    path: Option<std::ffi::OsString>,
    current_exe: Option<PathBuf>,
}

impl Launch {
    fn from_env() -> Self {
        Self {
            appimage: std::env::var_os("APPIMAGE").map(PathBuf::from),
            path: std::env::var_os("PATH"),
            current_exe: std::env::current_exe().ok(),
        }
    }

    fn exec_line(&self) -> String {
        let cmd = if let Some(appimage) = &self.appimage {
            quote(appimage)
        } else if self.on_path() || self.current_exe.is_none() {
            BIN.to_string()
        } else {
            // Not installed anywhere on PATH (a dev build): the binary itself.
            quote(self.current_exe.as_deref().unwrap_or(Path::new(BIN)))
        };
        format!("{cmd} {AUTOSTART_ARG}")
    }

    fn on_path(&self) -> bool {
        self.path
            .as_deref()
            .is_some_and(|p| std::env::split_paths(p).any(|dir| is_executable(&dir.join(BIN))))
    }
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    p.metadata()
        .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Quote an `Exec` argument per the desktop entry spec when it needs it.
fn quote(p: &Path) -> String {
    // `%` starts a field code anywhere in `Exec`, quoted or not.
    let s = p.to_string_lossy().replace('%', "%%");
    if s.chars()
        .any(|c| c.is_whitespace() || "\"'\\$`<>~|&;*?#()".contains(c))
    {
        let escaped = s
            .replace('\\', "\\\\\\\\")
            .replace('"', "\\\\\"")
            .replace('`', "\\\\`")
            .replace('$', "\\\\$");
        format!("\"{escaped}\"")
    } else {
        s
    }
}

fn render(exec: &str) -> String {
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Kasumi Proxy\n\
         Comment=Start Kasumi Proxy in the tray\n\
         Exec={exec}\n\
         Icon=kasumi-proxy\n\
         Terminal=false\n\
         StartupNotify=false\n\
         X-GNOME-Autostart-enabled=true\n\
         Hidden=false\n"
    )
}

fn key<'a>(entry: &'a str, name: &str) -> Option<&'a str> {
    entry
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix('='))
        .map(str::trim)
}

/// `$XDG_CONFIG_HOME/autostart`, falling back to `~/.config/autostart`.
fn autostart_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| Path::new(v).is_absolute())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| Path::new(&h).join(".config")))?;
    Some(base.join("autostart"))
}

fn is_enabled_in(dir: &Path) -> bool {
    // A desktop environment's own autostart editor disables an entry by setting
    // `Hidden=true` rather than deleting it.
    std::fs::read_to_string(dir.join(ENTRY))
        .is_ok_and(|e| !key(&e, "Hidden").is_some_and(|v| v.eq_ignore_ascii_case("true")))
}

fn set_enabled_in(dir: &Path, launch: &Launch, on: bool) -> io::Result<()> {
    let file = dir.join(ENTRY);
    if on {
        std::fs::create_dir_all(dir)?;
        std::fs::write(file, render(&launch.exec_line()))
    } else {
        match std::fs::remove_file(file) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// Carry an entry written by an older build over to the current form: the
/// plugin's entry is replaced, and our own is rewritten when its `Exec` no longer
/// matches (an AppImage that moved, a dev build now installed).
fn heal_in(dir: &Path, launch: &Launch) -> io::Result<()> {
    let legacy = dir.join(LEGACY_ENTRY);
    if legacy.exists() {
        std::fs::remove_file(&legacy)?;
        return set_enabled_in(dir, launch, true);
    }
    if let Ok(entry) = std::fs::read_to_string(dir.join(ENTRY))
        && is_enabled_in(dir)
        && key(&entry, "Exec") != Some(launch.exec_line().as_str())
    {
        set_enabled_in(dir, launch, true)?;
    }
    Ok(())
}

fn no_dir() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no $HOME for the autostart entry")
}

pub(crate) fn is_enabled() -> bool {
    autostart_dir().is_some_and(|d| is_enabled_in(&d))
}

pub(crate) fn set_enabled(on: bool) -> io::Result<()> {
    set_enabled_in(
        &autostart_dir().ok_or_else(no_dir)?,
        &Launch::from_env(),
        on,
    )
}

pub(crate) fn heal() -> io::Result<()> {
    heal_in(&autostart_dir().ok_or_else(no_dir)?, &Launch::from_env())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(appimage: Option<&str>, path: Option<&Path>, exe: &str) -> Launch {
        Launch {
            appimage: appimage.map(PathBuf::from),
            path: path.map(|p| p.as_os_str().to_owned()),
            current_exe: Some(PathBuf::from(exe)),
        }
    }

    fn fake_bin(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join(BIN);
        std::fs::write(&bin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn exec_prefers_appimage_then_path_then_own_binary() {
        let bin = tempfile::tempdir().unwrap();
        fake_bin(bin.path());
        let store = "/nix/store/abc-kasumi-desktop/bin/.kasumi-desktop-wrapped";

        let l = launch(
            Some("/home/u/Apps/Kasumi Proxy.AppImage"),
            Some(bin.path()),
            store,
        );
        assert_eq!(
            l.exec_line(),
            "\"/home/u/Apps/Kasumi Proxy.AppImage\" --autostart"
        );

        // NixOS: the running binary is the unwrapped store file, but the wrapper
        // is on PATH under the plain name — the entry must use the name.
        let l = launch(None, Some(bin.path()), store);
        assert_eq!(l.exec_line(), "kasumi-desktop --autostart");

        let empty = tempfile::tempdir().unwrap();
        let l = launch(
            None,
            Some(empty.path()),
            "/home/u/src/target/debug/kasumi-desktop",
        );
        assert_eq!(
            l.exec_line(),
            "/home/u/src/target/debug/kasumi-desktop --autostart"
        );
    }

    #[test]
    fn enable_disable_and_hidden() {
        let dir = tempfile::tempdir().unwrap();
        let auto = dir.path().join("autostart");
        let l = launch(None, None, "/usr/bin/kasumi-desktop");
        assert!(!is_enabled_in(&auto));

        set_enabled_in(&auto, &l, true).unwrap();
        assert!(is_enabled_in(&auto));
        let entry = std::fs::read_to_string(auto.join(ENTRY)).unwrap();
        assert_eq!(
            key(&entry, "Exec"),
            Some("/usr/bin/kasumi-desktop --autostart")
        );
        assert_eq!(key(&entry, "Type"), Some("Application"));

        std::fs::write(
            auto.join(ENTRY),
            entry.replace("Hidden=false", "Hidden=true"),
        )
        .unwrap();
        assert!(!is_enabled_in(&auto));

        set_enabled_in(&auto, &l, false).unwrap();
        assert!(!auto.join(ENTRY).exists());
        // Disabling twice is not an error.
        set_enabled_in(&auto, &l, false).unwrap();
    }

    #[test]
    fn heal_replaces_the_plugin_entry_and_a_stale_exec() {
        let dir = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        fake_bin(bin.path());
        let l = launch(
            None,
            Some(bin.path()),
            "/nix/store/new/bin/.kasumi-desktop-wrapped",
        );

        std::fs::write(
            dir.path().join(LEGACY_ENTRY),
            "[Desktop Entry]\nExec=/nix/store/old/bin/.kasumi-desktop-wrapped \n",
        )
        .unwrap();
        heal_in(dir.path(), &l).unwrap();
        assert!(!dir.path().join(LEGACY_ENTRY).exists());
        let entry = std::fs::read_to_string(dir.path().join(ENTRY)).unwrap();
        assert_eq!(key(&entry, "Exec"), Some("kasumi-desktop --autostart"));

        std::fs::write(dir.path().join(ENTRY), render("/old/path --autostart")).unwrap();
        heal_in(dir.path(), &l).unwrap();
        let entry = std::fs::read_to_string(dir.path().join(ENTRY)).unwrap();
        assert_eq!(key(&entry, "Exec"), Some("kasumi-desktop --autostart"));

        // A disabled (Hidden) entry is left as the user set it.
        let hidden = render("/old/path --autostart").replace("Hidden=false", "Hidden=true");
        std::fs::write(dir.path().join(ENTRY), &hidden).unwrap();
        heal_in(dir.path(), &l).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join(ENTRY)).unwrap(),
            hidden
        );
    }
}
