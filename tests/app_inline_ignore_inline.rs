use std::process::Command;

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn inline_ignore_suppresses_matching_finding() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/baseline/suppressed_inline.txt");
    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--no-cache")
        .arg("--lang")
        .arg("go")
        .arg(&source_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
}

#[test]
fn show_ignored_reports_suppressed_finding_as_info() {
    let root = helpers::inline_ignore::unique_temp_root("inline-show-ignored");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    helpers::inline_ignore::write_vulnerable_go(&source_path, "// slopguard-ignore: all");

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--show-ignored")
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--no-cache")
        .arg("--lang")
        .arg("go")
        .arg(&source_path)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("\"rule_id\":\"CWE-78\""),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("\"severity\":\"info\""),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("suppressed"), "stdout:\n{stdout}");

    std::fs::remove_dir_all(root).unwrap();
}
