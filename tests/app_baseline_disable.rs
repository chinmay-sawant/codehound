mod helpers;

use helpers::baseline::{
    TempProject, parse_findings, run_codehound, save_baseline, setup_temp_project,
};

const BASELINE_FILE: &str = ".codehound-baseline.json";
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
    run_codehound(&args, project.path())
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
        "codehound.toml",
        "[codehound]\n[codehound.baseline]\nenabled = false\n",
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
        "codehound.toml",
        "[codehound]\n[codehound.baseline]\npath = \"custom-baseline.json\"\n",
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
fn baseline_save_mode_ignores_disabled_config() {
    let project = setup_temp_project(&["sample.py"]);
    project.write_file(
        "codehound.toml",
        "[codehound]\n[codehound.baseline]\nenabled = false\n",
    );

    let output = run_codehound(
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
