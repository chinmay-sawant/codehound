mod helpers;

use helpers::baseline::{
    TempProject, parse_findings, run_slopguard, save_baseline, setup_temp_project,
};

const BASELINE_FILE: &str = ".slopguard-baseline.json";
const SCAN_ARGS: &[&str] = &[
    "--format",
    "json",
    "--no-context",
    "--no-chunks",
    "--lang",
    "python",
];

fn assert_success(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn scan_with_args(project: &TempProject, extra_args: &[&str]) -> std::process::Output {
    let mut args = SCAN_ARGS.to_vec();
    args.extend_from_slice(extra_args);
    run_slopguard(&args, project.path())
}

#[test]
fn baseline_save_then_filter_suppresses_existing_findings() {
    let project = setup_temp_project(&["sample.py"]);

    save_baseline(&project, "sample.py", BASELINE_FILE);
    assert!(project.join(BASELINE_FILE).exists());

    let output = scan_with_args(&project, &["--baseline-file", BASELINE_FILE, "sample.py"]);

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("suppressed 1"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn corrupted_baseline_warns_and_scan_proceeds_unfiltered() {
    let project = setup_temp_project(&["sample.py"]);
    project.write_file(BASELINE_FILE, "{not-json");

    let output = scan_with_args(&project, &["--baseline-file", BASELINE_FILE, "sample.py"]);

    assert_eq!(output.status.code(), Some(1));
    let findings = parse_findings(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SLOP101");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("warning: could not load baseline"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn no_baseline_flag_disables_even_explicit_baseline_file() {
    let project = setup_temp_project(&["sample.py"]);
    save_baseline(&project, "sample.py", BASELINE_FILE);

    let output = scan_with_args(
        &project,
        &[
            "--no-baseline",
            "--baseline-file",
            BASELINE_FILE,
            "sample.py",
        ],
    );

    assert_eq!(output.status.code(), Some(1));
    let findings = parse_findings(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SLOP101");
}

#[test]
fn config_baseline_disabled_prevents_auto_loading() {
    let project = setup_temp_project(&["sample.py"]);
    save_baseline(&project, "sample.py", BASELINE_FILE);
    project.write_file(
        "slopguard.toml",
        "[slopguard]\n[slopguard.baseline]\nenabled = false\n",
    );

    let output = scan_with_args(&project, &["sample.py"]);

    assert_eq!(output.status.code(), Some(1));
    let findings = parse_findings(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SLOP101");
}

#[test]
fn config_baseline_path_is_used_when_cli_path_absent() {
    let project = setup_temp_project(&["sample.py"]);
    save_baseline(&project, "sample.py", "custom-baseline.json");
    assert!(project.join("custom-baseline.json").exists());
    project.write_file(
        "slopguard.toml",
        "[slopguard]\n[slopguard.baseline]\npath = \"custom-baseline.json\"\n",
    );

    let output = scan_with_args(&project, &["sample.py"]);

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("custom-baseline.json"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn default_baseline_auto_discovery_suppresses_findings() {
    let project = setup_temp_project(&["sample.py"]);

    let save = run_slopguard(
        &[
            "--baseline",
            "--no-context",
            "--no-chunks",
            "--lang",
            "python",
            "sample.py",
        ],
        project.path(),
    );
    assert_success(&save);
    assert!(project.join(BASELINE_FILE).exists());

    let output = scan_with_args(&project, &["sample.py"]);

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("suppressed 1"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn baseline_save_mode_ignores_disabled_config() {
    let project = setup_temp_project(&["sample.py"]);
    project.write_file(
        "slopguard.toml",
        "[slopguard]\n[slopguard.baseline]\nenabled = false\n",
    );

    let output = run_slopguard(
        &[
            "--baseline",
            "--no-context",
            "--no-chunks",
            "--lang",
            "python",
            "sample.py",
        ],
        project.path(),
    );

    assert_success(&output);
    assert!(project.join(BASELINE_FILE).exists());
}

#[test]
fn baseline_allows_new_findings_not_in_baseline() {
    let project = setup_temp_project(&["sample.py"]);
    save_baseline(&project, "sample.py", BASELINE_FILE);
    project.write_python_finding("new.py", "other");

    let output = scan_with_args(
        &project,
        &["--baseline-file", BASELINE_FILE, "sample.py", "new.py"],
    );

    assert_eq!(output.status.code(), Some(1));
    let findings = parse_findings(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SLOP101");
    assert!(
        findings[0].file.ends_with("new.py"),
        "findings:\n{findings:?}"
    );
}

#[test]
fn unsupported_baseline_version_warns_and_skips_filtering() {
    let project = setup_temp_project(&["sample.py"]);
    save_baseline(&project, "sample.py", BASELINE_FILE);

    let baseline_path = project.join(BASELINE_FILE);
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

    let output = scan_with_args(&project, &["--baseline-file", BASELINE_FILE, "sample.py"]);

    assert_eq!(output.status.code(), Some(1));
    let findings = parse_findings(&String::from_utf8_lossy(&output.stdout));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "SLOP101");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unsupported version 2"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn older_tool_version_warns_but_still_filters() {
    let project = setup_temp_project(&["sample.py"]);
    save_baseline(&project, "sample.py", BASELINE_FILE);

    let baseline_path = project.join(BASELINE_FILE);
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

    let output = scan_with_args(&project, &["--baseline-file", BASELINE_FILE, "sample.py"]);

    assert_success(&output);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("generated by slopguard 0.0.0"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn scan_errors_exit_three() {
    let project = TempProject::new("scan-error-exit");
    project.write_file("bad.py", [0xff, 0xfe]);

    let output = scan_with_args(&project, &["bad.py"]);

    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("could not be scanned"),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
