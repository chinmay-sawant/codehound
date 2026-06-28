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
fn baseline_allows_new_findings_not_in_baseline() {
    let project = setup_temp_project(&["sample.py"]);
    save_baseline(&project, "sample.py", BASELINE_FILE);
    project.write_python_finding("new.py");

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
