use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_root(test_name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("slopguard-{test_name}-{unique}"))
}

fn write_python_finding(path: &std::path::Path, pattern_name: &str) {
    std::fs::write(
        path,
        format!("import re\n\nfor item in items:\n    re.compile({pattern_name})\n"),
    )
    .unwrap();
}

fn save_baseline(
    root: &std::path::Path,
    source_path: &std::path::Path,
    baseline_path: &std::path::Path,
) {
    let save = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .current_dir(root)
        .arg("--baseline")
        .arg("--baseline-file")
        .arg(baseline_path)
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg(source_path)
        .output()
        .unwrap();

    assert!(
        save.status.success(),
        "save failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&save.stdout),
        String::from_utf8_lossy(&save.stderr)
    );
}

#[test]
fn baseline_save_then_filter_suppresses_existing_findings() {
    let root = unique_temp_root("baseline-workflow");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    let baseline_path = root.join(".slopguard-baseline.json");

    save_baseline(&root, &source_path, &baseline_path);
    assert!(baseline_path.exists());

    let filtered = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--baseline-file")
        .arg(&baseline_path)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg(&source_path)
        .output()
        .unwrap();

    assert!(
        filtered.status.success(),
        "filtered run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&filtered.stdout),
        String::from_utf8_lossy(&filtered.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&filtered.stdout), "");
    assert!(
        String::from_utf8_lossy(&filtered.stderr).contains("suppressed 1"),
        "stderr:\n{}",
        String::from_utf8_lossy(&filtered.stderr)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupted_baseline_warns_and_scan_proceeds_unfiltered() {
    let root = unique_temp_root("baseline-corrupt");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    let baseline_path = root.join(".slopguard-baseline.json");
    std::fs::write(&baseline_path, "{not-json").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--baseline-file")
        .arg(&baseline_path)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg(&source_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"rule_id\":\"SLOP101\""),
        "stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("warning: could not load baseline"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn no_baseline_flag_disables_even_explicit_baseline_file() {
    let root = unique_temp_root("baseline-no-baseline");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    let baseline_path = root.join(".slopguard-baseline.json");
    save_baseline(&root, &source_path, &baseline_path);

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--no-baseline")
        .arg("--baseline-file")
        .arg(&baseline_path)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg(&source_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"rule_id\":\"SLOP101\""),
        "stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn config_baseline_disabled_prevents_auto_loading() {
    let root = unique_temp_root("baseline-config-disabled");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    let baseline_path = root.join(".slopguard-baseline.json");
    save_baseline(&root, &source_path, &baseline_path);
    std::fs::write(
        root.join("slopguard.toml"),
        "[slopguard]\n[slopguard.baseline]\nenabled = false\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .current_dir(&root)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg("sample.py")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"rule_id\":\"SLOP101\""),
        "stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn config_baseline_path_is_used_when_cli_path_absent() {
    let root = unique_temp_root("baseline-config-path");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    let baseline_path = root.join("custom-baseline.json");
    let save = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .current_dir(&root)
        .arg("--baseline")
        .arg("--baseline-file")
        .arg("custom-baseline.json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg("sample.py")
        .output()
        .unwrap();
    assert!(
        save.status.success(),
        "save failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&save.stdout),
        String::from_utf8_lossy(&save.stderr)
    );
    assert!(baseline_path.exists());
    std::fs::write(
        root.join("slopguard.toml"),
        "[slopguard]\n[slopguard.baseline]\npath = \"custom-baseline.json\"\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .current_dir(&root)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg("sample.py")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("custom-baseline.json"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn default_baseline_auto_discovery_suppresses_findings() {
    let root = unique_temp_root("baseline-auto-discovery");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");

    let save = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .current_dir(&root)
        .arg("--baseline")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg("sample.py")
        .output()
        .unwrap();
    assert!(
        save.status.success(),
        "save failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&save.stdout),
        String::from_utf8_lossy(&save.stderr)
    );
    assert!(root.join(".slopguard-baseline.json").exists());

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .current_dir(&root)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg("sample.py")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("suppressed 1"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn baseline_save_mode_ignores_disabled_config() {
    let root = unique_temp_root("baseline-save-config-disabled");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    std::fs::write(
        root.join("slopguard.toml"),
        "[slopguard]\n[slopguard.baseline]\nenabled = false\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .current_dir(&root)
        .arg("--baseline")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg("sample.py")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.join(".slopguard-baseline.json").exists());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn baseline_allows_new_findings_not_in_baseline() {
    let root = unique_temp_root("baseline-new-finding");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    let baseline_path = root.join(".slopguard-baseline.json");
    save_baseline(&root, &source_path, &baseline_path);

    let second_path = root.join("new.py");
    write_python_finding(&second_path, "other");

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--baseline-file")
        .arg(&baseline_path)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg(&source_path)
        .arg(&second_path)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stdout.matches("\"rule_id\":\"SLOP101\"").count(),
        1,
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("new.py"), "stdout:\n{stdout}");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unsupported_baseline_version_warns_and_skips_filtering() {
    let root = unique_temp_root("baseline-version-skip");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    let baseline_path = root.join(".slopguard-baseline.json");
    save_baseline(&root, &source_path, &baseline_path);

    let mut baseline_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline_path).unwrap()).unwrap();
    baseline_json["version"] = serde_json::Value::String("2".to_string());
    std::fs::write(
        &baseline_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&baseline_json).unwrap()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--baseline-file")
        .arg(&baseline_path)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg(&source_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("\"rule_id\":\"SLOP101\""),
        "stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported version 2"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn older_tool_version_warns_but_still_filters() {
    let root = unique_temp_root("baseline-tool-version");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("sample.py");
    write_python_finding(&source_path, "item");
    let baseline_path = root.join(".slopguard-baseline.json");
    save_baseline(&root, &source_path, &baseline_path);

    let mut baseline_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline_path).unwrap()).unwrap();
    baseline_json["tool_version"] = serde_json::Value::String("0.0.0".to_string());
    std::fs::write(
        &baseline_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&baseline_json).unwrap()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--baseline-file")
        .arg(&baseline_path)
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg(&source_path)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("generated by slopguard 0.0.0"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn scan_errors_exit_three() {
    let root = unique_temp_root("scan-error-exit");
    std::fs::create_dir_all(&root).unwrap();
    let source_path = root.join("bad.py");
    std::fs::write(&source_path, [0xff, 0xfe]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .arg("--format")
        .arg("json")
        .arg("--no-context")
        .arg("--no-chunks")
        .arg("--lang")
        .arg("python")
        .arg(&source_path)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not be scanned"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::remove_dir_all(root).unwrap();
}
