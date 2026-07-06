use std::process::Command;

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn file_ignore_suppresses_all_findings() {
    let root = helpers::unique_temp_root("file-ignore-all");
    let source_dir = root.join("sample");
    std::fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("sample.go");
    helpers::write_go_source(&source_path, "// codehound-ignore-file\n");

    let output = Command::new(env!("CARGO_BIN_EXE_codehound"))
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
    let root = helpers::unique_temp_root("file-ignore-rule-list");
    let source_dir = root.join("sample");
    std::fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("sample.go");
    helpers::write_go_source(&source_path, "// codehound-ignore-file: CWE-78\n");

    let output = Command::new(env!("CARGO_BIN_EXE_codehound"))
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
    let root = helpers::unique_temp_root("file-ignore-show");
    let source_dir = root.join("sample");
    std::fs::create_dir_all(&source_dir).unwrap();
    let source_path = source_dir.join("sample.go");
    helpers::write_go_source(&source_path, "// codehound-ignore-file: all\n");

    let output = Command::new(env!("CARGO_BIN_EXE_codehound"))
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

#[test]
fn inline_ignore_suppresses_matching_finding() {
    let source_path =
        helpers::assert_fixture_materializes("tests/fixtures/go/baseline/suppressed_inline.txt");
    let output = Command::new(env!("CARGO_BIN_EXE_codehound"))
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
    let root = helpers::unique_temp_root("inline-show-ignored");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    std::fs::write(
        &source_path,
        r#"package sample

import (
	"net/http"
	"os/exec"
)

func TraceRoute(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// codehound-ignore: all
	cmd := exec.Command("sh", "-c", "traceroute -m 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, string(out), http.StatusBadRequest)
		return
	}
	_, _ = w.Write(out)
}
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_codehound"))
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
