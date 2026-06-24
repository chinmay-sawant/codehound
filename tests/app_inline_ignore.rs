use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "helpers/mod.rs"]
mod helpers;

fn unique_temp_root(test_name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("slopguard-{test_name}-{unique}"))
}

fn write_vulnerable_go(path: &std::path::Path, ignore: &str) {
    std::fs::write(
        path,
        format!(
            r#"package sample

import (
	"net/http"
	"os/exec"
)

func TraceRoute(w http.ResponseWriter, r *http.Request) {{
	host := r.URL.Query().Get("host")
	{ignore}
	cmd := exec.Command("sh", "-c", "traceroute -m 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {{
		http.Error(w, string(out), http.StatusBadRequest)
		return
	}}
	_, _ = w.Write(out)
}}
"#
        ),
    )
    .unwrap();
}

fn write_vulnerable_go_with_header(path: &std::path::Path, header: &str) {
    std::fs::write(
        path,
        format!(
            r#"{header}package sample

import (
	"net/http"
	"os/exec"
)

func TraceRoute(w http.ResponseWriter, r *http.Request) {{
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "traceroute -m 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {{
		http.Error(w, string(out), http.StatusBadRequest)
		return
	}}
	w.Write(out)
}}
"#
        ),
    )
    .unwrap();
}

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
    let root = unique_temp_root("inline-show-ignored");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    write_vulnerable_go(&source_path, "// slopguard-ignore: all");

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

#[test]
fn file_ignore_suppresses_all_findings() {
    let root = unique_temp_root("file-ignore-all");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    write_vulnerable_go_with_header(&source_path, "// slopguard-ignore-file\n");

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
    let root = unique_temp_root("file-ignore-rule-list");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    write_vulnerable_go_with_header(&source_path, "// slopguard-ignore-file: CWE-78\n");

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
    let root = unique_temp_root("file-ignore-show");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.go");
    write_vulnerable_go_with_header(&source_path, "// slopguard-ignore-file: all\n");

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
