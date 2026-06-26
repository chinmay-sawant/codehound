use std::process::Command;

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn file_ignore_suppresses_all_findings() {
    let root = helpers::inline_ignore::unique_temp_root("file-ignore-all");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    helpers::inline_ignore::write_vulnerable_go_with_header(
        &source_path,
        "// slopguard-ignore-file\n",
    );

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

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn file_ignore_rule_list_suppresses_matching_finding() {
    let root = helpers::inline_ignore::unique_temp_root("file-ignore-rule-list");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    helpers::inline_ignore::write_vulnerable_go_with_header(
        &source_path,
        "// slopguard-ignore-file: CWE-78\n",
    );

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

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn show_ignored_reports_file_ignored_finding_as_info() {
    let root = helpers::inline_ignore::unique_temp_root("file-ignore-show");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    helpers::inline_ignore::write_vulnerable_go_with_header(
        &source_path,
        "// slopguard-ignore-file: all\n",
    );

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
