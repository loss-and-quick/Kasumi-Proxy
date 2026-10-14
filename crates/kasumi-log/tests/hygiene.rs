//! Nothing in the workspace prints for itself.
//!
//! The facade exists so a record can be filtered, formatted the same way in every
//! process and kept out of the wrong file — all of which a bare `println!` skips.
//! Most of the tree had none, but the ones that appeared were exactly the places
//! where a bug report would otherwise go quiet: a helper that dies before its
//! logger exists, a CLI whose stdout *is* the protocol. The first kind stays, with
//! its reason written down here; the second kind is a protocol, not a log line.
//!
//! Test modules are exempt: a test that prints is the test's output.

use std::fs;
use std::path::{Path, PathBuf};

/// The ad-hoc printers. `dbg!` is here because it also bypasses the facade and
/// nobody remembers to remove it.
const PRINT_MACROS: [&str; 3] = ["println!(", "eprintln!(", "dbg!"];

/// Printing that is not a log line: the facility the program talks to, or the one
/// moment before its logger exists. Keep the reason — this list is meant to shrink.
const ALLOWED: [(&str, &str); 5] = [
    (
        "crates/kasumi-daemon/src/run.rs",
        "stdout is the JSON protocol the module's scripts read",
    ),
    (
        "src-tauri/src/bin/kasumi-helper.rs",
        "arg parsing fails before the logger is installed",
    ),
    (
        "src-tauri/src/desktop/privhelper/entry.rs",
        "arg parsing fails before the logger is installed",
    ),
    (
        "src-tauri/src/desktop/privhelper/service.rs",
        "the SCM dispatcher fails before the logger is installed",
    ),
    (
        "src-tauri/examples/codegen.rs",
        "runs under `cargo run`, writes a report to the terminal",
    ),
];

#[test]
fn no_ad_hoc_printing_outside_test_modules() {
    let root = workspace_root();
    let mut offenders = Vec::new();
    for tree in ["crates", "src-tauri/src", "src-tauri/examples"] {
        let mut files = Vec::new();
        collect_rust_files(&root.join(tree), &mut files);
        for file in files {
            let relative = file
                .strip_prefix(&root)
                .unwrap_or(&file)
                .to_string_lossy()
                .into_owned();
            if ALLOWED.iter().any(|(allowed, _)| *allowed == relative) {
                continue;
            }
            let content = fs::read_to_string(&file).unwrap_or_default();
            // Everything from the first test module on is the test's own output.
            let production = match content.find("#[cfg(test)]") {
                Some(start) => &content[..start],
                None => content.as_str(),
            };
            for (number, line) in production.lines().enumerate() {
                let trimmed = line.trim_start();
                if PRINT_MACROS
                    .iter()
                    .any(|macro_| trimmed.starts_with(macro_))
                {
                    offenders.push(format!("{}:{}: {}", relative, number + 1, trimmed));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "print instead of logging (use kasumi_log::ks_*):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_allowlist_has_no_stale_entries() {
    let root = workspace_root();
    for (path, reason) in ALLOWED {
        let content = fs::read_to_string(root.join(path))
            .unwrap_or_else(|e| panic!("allowed path {path} no longer exists: {e}"));
        assert!(
            PRINT_MACROS.iter().any(|macro_| content.contains(macro_)),
            "{path} is allowlisted ({reason}) but no longer prints"
        );
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // `tests/` holds test binaries; `target/` holds build output.
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            if name != "tests" && name != "target" {
                collect_rust_files(&path, files);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            files.push(path);
        }
    }
}
