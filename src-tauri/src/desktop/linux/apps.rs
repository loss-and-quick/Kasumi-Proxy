//! The programs a Linux desktop can launch, for the per-app filter: its XDG desktop
//! entries (`applications/*.desktop` under the user's and the system's data dirs,
//! Flatpak and Snap exports included), their icons found in the user's icon theme
//! with `freedesktop-icons`. Each
//! visible application entry becomes one app keyed by the program its `Exec` runs;
//! the routing matches that program by process name (`kasumi_core::app_process`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use kasumi_backend::platform::AppInfo;

/// Icons above this size are left out rather than bloating the list.
const MAX_ICON_BYTES: u64 = 128 * 1024;

pub async fn list_apps() -> Vec<AppInfo> {
    tokio::task::spawn_blocking(|| {
        let theme = freedesktop_icons::default_theme_gtk();
        let icon = |name: &str| icon_data_url(name, theme.as_deref());
        scan(&data_dirs(), &path_dirs(), &locales(), &icon)
    })
    .await
    .unwrap_or_default()
}

/// The XDG data dirs in precedence order (the user's first), plus the Flatpak and
/// Snap export dirs a session may not list.
fn data_dirs() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut dirs = Vec::new();
    match std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        Some(d) => dirs.push(PathBuf::from(d)),
        None => dirs.extend(home.as_ref().map(|h| h.join(".local/share"))),
    }
    let system = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    dirs.extend(
        system
            .split(':')
            .filter(|d| !d.is_empty())
            .map(PathBuf::from),
    );
    dirs.extend(home.map(|h| h.join(".local/share/flatpak/exports/share")));
    dirs.push("/var/lib/flatpak/exports/share".into());
    dirs.push("/var/lib/snapd/desktop".into());
    let mut seen = HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));
    dirs
}

fn path_dirs() -> Vec<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default()
}

/// `Name[...]` keys to try, most specific first (`ru_RU`, then `ru`).
fn locales() -> Vec<String> {
    let lang = ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
        .unwrap_or_default();
    let base = lang.split(['.', '@']).next().unwrap_or("");
    let mut out = Vec::new();
    if !base.is_empty() && base != "C" && base != "POSIX" {
        out.push(base.to_string());
        if let Some((l, _)) = base.split_once('_') {
            out.push(l.to_string());
        }
    }
    out
}

fn scan(
    data_dirs: &[PathBuf],
    path: &[PathBuf],
    locales: &[String],
    icon: &dyn Fn(&str) -> Option<String>,
) -> Vec<AppInfo> {
    let mut ids = HashSet::new();
    let mut exes = HashSet::new();
    let mut apps = Vec::new();
    for dir in data_dirs {
        let root = dir.join("applications");
        let mut files = Vec::new();
        collect_entries(&root, &root, &mut files);
        files.sort();
        for (id, file) in files {
            // XDG: the first dir that has an id wins, even when it hides the entry.
            if !ids.insert(id.clone()) {
                continue;
            }
            let Some(app) = std::fs::read_to_string(&file)
                .ok()
                .and_then(|text| to_app(&id, &text, path, locales, icon))
            else {
                continue;
            };
            if exes.insert(app.exe.clone()) {
                apps.push(app);
            }
        }
    }
    apps
}

/// Every `*.desktop` under `dir`, with its desktop-file id (the path below the
/// `applications` dir, `/` turned into `-`).
fn collect_entries(root: &Path, dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for e in read.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_entries(root, &p, out);
        } else if p.extension().is_some_and(|x| x == "desktop")
            && let Ok(rel) = p.strip_prefix(root)
        {
            let id = rel
                .to_string_lossy()
                .trim_end_matches(".desktop")
                .replace('/', "-");
            out.push((id, p));
        }
    }
}

/// The keys of a desktop file's `[Desktop Entry]` group (other groups, such as
/// `[Desktop Action …]`, carry their own `Exec`).
fn entry_keys(text: &str) -> Vec<(&str, &str)> {
    let mut in_group = false;
    let mut keys = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_group = line == "[Desktop Entry]";
        } else if in_group
            && !line.starts_with('#')
            && let Some((k, v)) = line.split_once('=')
        {
            keys.push((k.trim(), v.trim()));
        }
    }
    keys
}

fn to_app(
    id: &str,
    text: &str,
    path: &[PathBuf],
    locales: &[String],
    icon: &dyn Fn(&str) -> Option<String>,
) -> Option<AppInfo> {
    let keys = entry_keys(text);
    let get = |key: &str| keys.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    if get("Type") != Some("Application")
        || get("NoDisplay") == Some("true")
        || get("Hidden") == Some("true")
    {
        return None;
    }
    let program = exec_program(&exec_args(get("Exec")?))?;
    let label = locales
        .iter()
        .find_map(|l| get(&format!("Name[{l}]")))
        .or_else(|| get("Name"))
        .map(unescape);
    Some(AppInfo {
        pkg: id.to_string(),
        exe: Some(resolve(&program, path)),
        label,
        icon: get("Icon").and_then(icon),
        ..Default::default()
    })
}

/// Split an `Exec` value into arguments per the desktop-entry spec: string escapes
/// first, then double-quoted arguments with their own backslash escapes.
fn exec_args(exec: &str) -> Vec<String> {
    let unescaped = unescape(exec);
    let mut args = Vec::new();
    let mut cur = String::new();
    let (mut has, mut quoted) = (false, false);
    let mut chars = unescaped.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                has = true;
            }
            '\\' if quoted => cur.extend(chars.next()),
            c if c.is_whitespace() && !quoted => {
                if has || !cur.is_empty() {
                    args.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => cur.push(c),
        }
    }
    if has || !cur.is_empty() {
        args.push(cur);
    }
    args
}

/// Undo a desktop-entry string's escapes (`\\s`, `\\n`, `\\t`, `\\\\`). Any other
/// backslash is kept: in `Exec` it belongs to the argument quoting.
fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('s') => out.push(' '),
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some(o) => {
                out.push('\\');
                out.push(o);
            }
            None => {}
        }
    }
    out
}

/// The program an `Exec` line runs: past an `env VAR=… ` prefix, and the
/// `--command=` of a Flatpak launcher (`flatpak run --command=firefox …`).
fn exec_program(args: &[String]) -> Option<String> {
    let mut it = args.iter().map(String::as_str).peekable();
    if it
        .peek()
        .is_some_and(|a| a.rsplit('/').next() == Some("env"))
    {
        it.next();
        while it
            .peek()
            .is_some_and(|a| a.contains('=') && !a.starts_with('-'))
        {
            it.next();
        }
    }
    let program = it.next()?;
    if program.rsplit('/').next() == Some("flatpak") {
        return it
            .find_map(|a| a.strip_prefix("--command="))
            .map(str::to_string);
    }
    Some(program.to_string())
}

/// A bare program name found on `PATH`, else as given. Not canonicalized: on NixOS
/// the `PATH` entry (`/run/current-system/sw/bin/firefox`) outlives a rebuild, the
/// store path it links to doesn't.
fn resolve(program: &str, path: &[PathBuf]) -> String {
    if program.contains('/') {
        return program.to_string();
    }
    path.iter()
        .map(|d| d.join(program))
        .find(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

/// An icon as a `data:` URL: an absolute `Icon=` path, or the name looked up in
/// the user's icon theme (hicolor and `pixmaps` as the fallback).
fn icon_data_url(icon: &str, theme: Option<&str>) -> Option<String> {
    let file = if icon.starts_with('/') {
        PathBuf::from(icon)
    } else {
        let mut lookup = freedesktop_icons::lookup(icon).with_size(48).with_cache();
        if let Some(t) = theme {
            lookup = lookup.with_theme(t);
        }
        lookup.find()?
    };
    file_data_url(&file)
}

fn file_data_url(file: &Path) -> Option<String> {
    let mime = match file.extension()?.to_str()? {
        "png" => "image/png",
        "svg" => "image/svg+xml",
        _ => return None,
    };
    if std::fs::metadata(file).ok()?.len() > MAX_ICON_BYTES {
        return None;
    }
    let bytes = std::fs::read(file).ok()?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    Some(format!("data:{mime};base64,{b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(args: &[&str]) -> Option<String> {
        exec_program(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn splits_exec_like_the_spec() {
        assert_eq!(
            exec_args(r#""/opt/My App/app" --flag %F"#),
            ["/opt/My App/app", "--flag", "%F"]
        );
        assert_eq!(
            exec_args(r#"sh -c "echo \\"hi\\"""#),
            ["sh", "-c", "echo \"hi\""]
        );
    }

    #[test]
    fn finds_the_program_behind_exec() {
        assert_eq!(program(&["firefox"]).as_deref(), Some("firefox"));
        assert_eq!(
            program(&["env", "GDK_BACKEND=x11", "/usr/bin/telegram-desktop", "--"]).as_deref(),
            Some("/usr/bin/telegram-desktop")
        );
        assert_eq!(
            program(&[
                "/usr/bin/flatpak",
                "run",
                "--branch=stable",
                "--command=firefox",
                "org.mozilla.firefox",
            ])
            .as_deref(),
            Some("firefox")
        );
    }

    #[test]
    fn scans_entries_in_xdg_precedence() {
        let user = tempfile::tempdir().unwrap();
        let system = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let w = |dir: &Path, name: &str, body: &str| {
            let p = dir.join("applications").join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        std::fs::write(bin.path().join("firefox"), "").unwrap();
        w(
            system.path(),
            "firefox.desktop",
            "[Desktop Entry]\nType=Application\nName=Firefox\nName[ru]=Файрфокс\nExec=firefox %u\nIcon=firefox\n[Desktop Action new]\nExec=firefox --new\n",
        );
        // The user's copy of an id hides the system one.
        w(
            user.path(),
            "hidden.desktop",
            "[Desktop Entry]\nType=Application\nName=X\nExec=x\nNoDisplay=true\n",
        );
        w(
            system.path(),
            "hidden.desktop",
            "[Desktop Entry]\nType=Application\nName=X\nExec=x\n",
        );
        w(
            system.path(),
            "dolphin.desktop",
            "[Desktop Entry]\nType=Application\nName=Dolphin\nExec=\"/opt/kde apps/dolphin\" %U\n",
        );
        w(
            system.path(),
            "link.desktop",
            "[Desktop Entry]\nType=Link\nName=Site\nURL=https://x\n",
        );

        let icon = |name: &str| (name == "firefox").then(|| "data:icon".to_string());
        let apps = scan(
            &[user.path().into(), system.path().into()],
            &[bin.path().into()],
            &["ru".into()],
            &icon,
        );
        let ids: Vec<&str> = apps.iter().map(|a| a.pkg.as_str()).collect();
        assert_eq!(ids, ["dolphin", "firefox"]);
        assert_eq!(apps[0].exe.as_deref(), Some("/opt/kde apps/dolphin"));
        assert!(apps[0].icon.is_none());
        let ff = &apps[1];
        assert_eq!(
            ff.exe.as_deref(),
            Some(bin.path().join("firefox").to_str().unwrap())
        );
        assert_eq!(ff.label.as_deref(), Some("Файрфокс"));
        assert_eq!(ff.icon.as_deref(), Some("data:icon"));
    }

    #[test]
    fn icon_files_become_data_urls() {
        let dir = tempfile::tempdir().unwrap();
        let png = dir.path().join("a.png");
        std::fs::write(&png, [0x89, b'P', b'N', b'G']).unwrap();
        assert_eq!(
            icon_data_url(png.to_str().unwrap(), None).as_deref(),
            Some("data:image/png;base64,iVBORw==")
        );
        let xpm = dir.path().join("a.xpm");
        std::fs::write(&xpm, "x").unwrap();
        assert!(icon_data_url(xpm.to_str().unwrap(), None).is_none());
    }
}
