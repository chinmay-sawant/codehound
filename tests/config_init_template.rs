//! `codehound init` template must parse with the real config loader.

use std::path::Path;

use codehound::engine::CodehoundConfig;

#[test]
fn init_template_parses_as_codehound_config() {
    let template = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates/codehound.toml");
    assert!(template.is_file(), "missing {}", template.display());
    CodehoundConfig::load(&template)
        .unwrap_or_else(|e| panic!("templates/codehound.toml must parse: {e}"));
}

#[test]
fn fail_on_rejects_unknown_values() {
    let dir = tempfile_dir();
    let path = dir.join("codehound.toml");
    std::fs::write(
        &path,
        r#"[codehound]
fail_on = "typo-medium"
"#,
    )
    .unwrap();
    let err = CodehoundConfig::load(&path).expect_err("unknown fail_on must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("fail_on") || msg.contains("unknown"),
        "unexpected error: {msg}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn fail_on_accepts_known_values() {
    for value in ["none", "never", "medium", "warnings", "high", "strict"] {
        let dir = tempfile_dir();
        let path = dir.join("codehound.toml");
        std::fs::write(&path, format!("[codehound]\nfail_on = \"{value}\"\n")).unwrap();
        CodehoundConfig::load(&path)
            .unwrap_or_else(|e| panic!("fail_on={value:?} should parse: {e}"));
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn tempfile_dir() -> std::path::PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("codehound-init-template-{unique}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
