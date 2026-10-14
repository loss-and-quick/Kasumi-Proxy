//! What the shared sink writes to its log file. Its own test binary: the sink is
//! installed once per process.

use kasumi_log::{Area, LogConfig, init, ks_info};

#[test]
fn each_record_is_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.log");
    init(
        &LogConfig {
            to_stderr: false,
            panic_hook: false,
            ..LogConfig::default()
        }
        .with_file(&path),
    );

    ks_info!(Area::Lifecycle, "first");
    ks_info!(Area::Lifecycle, "second");
    log::logger().flush();

    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text:?}");
    assert!(lines[0].ends_with("first"), "{text:?}");
    assert!(lines[1].ends_with("second"), "{text:?}");
    assert!(text.ends_with("second\n"), "{text:?}");
}
