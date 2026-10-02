//! The programs a Windows desktop can launch, for the per-app filter: the Start
//! menu's shortcuts (all users' and the current user's) that point at an `.exe`.
//! The routing matches each by process name (`kasumi_core::app_process`).

use std::collections::HashSet;

use kasumi_backend::platform::AppInfo;
use serde::Deserialize;

/// Lists the shortcuts as JSON `[{name, exe, icon}]`, with the target's own icon
/// as base64 PNG. UTF-8 output so non-ASCII names survive the console codepage;
/// uninstaller shortcuts are left out.
const SCRIPT: &str = r#"
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Add-Type -AssemblyName System.Drawing
$sh = New-Object -ComObject WScript.Shell
$dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:APPDATA\Microsoft\Windows\Start Menu\Programs")
$out = foreach ($d in $dirs) {
  Get-ChildItem -LiteralPath $d -Recurse -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
    $t = $sh.CreateShortcut($_.FullName).TargetPath
    if ($t -and $t.ToLower().EndsWith('.exe') -and (Test-Path -LiteralPath $t) -and ($_.BaseName -notmatch 'uninstall|unins0')) {
      $icon = $null
      try {
        $ms = New-Object IO.MemoryStream
        [System.Drawing.Icon]::ExtractAssociatedIcon($t).ToBitmap().Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $icon = [Convert]::ToBase64String($ms.ToArray())
      } catch {}
      [pscustomobject]@{ name = $_.BaseName; exe = $t; icon = $icon }
    }
  }
}
ConvertTo-Json -Compress -InputObject @($out)
"#;

#[derive(Deserialize)]
struct Shortcut {
    name: String,
    exe: String,
    icon: Option<String>,
}

pub async fn list_apps() -> Vec<AppInfo> {
    parse(&super::routing::powershell(SCRIPT).await)
}

fn parse(json: &str) -> Vec<AppInfo> {
    let shortcuts: Vec<Shortcut> = serde_json::from_str(json).unwrap_or_default();
    let mut seen = HashSet::new();
    shortcuts
        .into_iter()
        .filter(|s| seen.insert(s.exe.to_ascii_lowercase()))
        .map(|s| AppInfo {
            pkg: s.name.clone(),
            exe: Some(s.exe),
            label: Some(s.name),
            icon: s.icon.map(|b64| format!("data:image/png;base64,{b64}")),
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_shortcuts_once_per_program() {
        let apps = parse(
            r#"[{"name":"Firefox","exe":"C:\\Program Files\\Mozilla Firefox\\firefox.exe","icon":"AAA="},
                {"name":"Firefox Private","exe":"C:\\Program Files\\Mozilla Firefox\\FIREFOX.EXE","icon":null},
                {"name":"Telegram","exe":"C:\\Users\\u\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe","icon":null}]"#,
        );
        assert_eq!(apps.len(), 2);
        assert_eq!(apps[0].label.as_deref(), Some("Firefox"));
        assert_eq!(apps[0].icon.as_deref(), Some("data:image/png;base64,AAA="));
        assert_eq!(apps[1].pkg, "Telegram");
        assert!(parse("").is_empty());
    }
}
