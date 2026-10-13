use std::{env, fs, path::PathBuf};

fn main() {
    let windows = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let mut attributes = tauri_build::Attributes::new();
    if windows {
        attributes = attributes
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
    }
    if let Err(error) = tauri_build::try_build(attributes) {
        panic!("{error:#}");
    }
    if windows {
        embed_app_manifest();
    }
}

/// tauri-build links its app manifest into the bins only, so the lib's test harness
/// and the examples start without Common Controls v6 and die at load resolving
/// comctl32's `TaskDialogIndirect` (STATUS_ENTRYPOINT_NOT_FOUND,
/// tauri-apps/tauri#13419). This links the same manifest, as the same resource
/// tauri-winres writes (ID 1, RT_MANIFEST, one quoted string per trimmed line),
/// into every artifact instead.
fn embed_app_manifest() {
    println!("cargo:rerun-if-changed=windows-app-manifest.xml");
    let manifest = fs::read_to_string("windows-app-manifest.xml")
        .expect("failed to read windows-app-manifest.xml");
    let mut rc = String::from("1 24\n{\n");
    for line in manifest.lines() {
        let line = line.trim().replace('\\', "\\\\").replace('"', "\"\"");
        rc.push_str(&format!("\" {line} \"\n"));
    }
    rc.push_str("}\n");
    let rc_path = PathBuf::from(env::var("OUT_DIR").unwrap()).join("app-manifest.rc");
    fs::write(&rc_path, rc).expect("failed to write app-manifest.rc");
    embed_resource::compile_for_everything(&rc_path, embed_resource::NONE)
        .manifest_required()
        .expect("failed to embed the Windows app manifest");
}
