//! CLI tests for `codehound rules --explain` / `--explain` maturity surface (§4.2 / #118).

use std::process::Command;

fn run_explain(rule_id: &str) -> String {
    let exe = env!("CARGO_BIN_EXE_codehound");
    let run = Command::new(exe)
        .args(["rules", "--explain", rule_id])
        .output()
        .unwrap_or_else(|e| panic!("run rules --explain {rule_id}: {e}"));
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    assert!(
        run.status.success(),
        "rules --explain {rule_id} failed\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    stdout
}

fn assert_explainability_fields(stdout: &str, rule_id: &str, maturity: &str) {
    assert!(
        stdout.contains(&format!("Rule ID:           {rule_id}")),
        "missing Rule ID for {rule_id}:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("Maturity:          {maturity}")),
        "missing Maturity {maturity} for {rule_id}:\n{stdout}"
    );
    assert!(
        stdout.contains("Pack eligibility:"),
        "missing Pack eligibility for {rule_id}:\n{stdout}"
    );
    assert!(
        stdout.contains("Status reason:"),
        "missing Status reason for {rule_id}:\n{stdout}"
    );
    assert!(
        stdout.contains("Documentation:"),
        "missing Documentation for {rule_id}:\n{stdout}"
    );
}

#[test]
fn cli_explain_taint_core_cwe_89() {
    let stdout = run_explain("CWE-89");
    assert_explainability_fields(&stdout, "CWE-89", "taint-core");
    assert!(stdout.contains("security"), "stdout:\n{stdout}");
    assert!(stdout.contains("recommended"), "stdout:\n{stdout}");
    assert!(stdout.contains("Analysis mode: taint"), "stdout:\n{stdout}");
}

#[test]
fn cli_explain_structural_cwe_41() {
    let stdout = run_explain("CWE-41");
    assert_explainability_fields(&stdout, "CWE-41", "structural");
    assert!(stdout.contains("security pack"), "stdout:\n{stdout}");
}

#[test]
fn cli_explain_heuristic_cwe_916() {
    let stdout = run_explain("CWE-916");
    assert_explainability_fields(&stdout, "CWE-916", "heuristic");
    assert!(
        !stdout.contains("quarantined from recommended"),
        "heuristic must not claim default-pack quarantine:\n{stdout}"
    );
}

#[test]
fn cli_explain_fixture_only_cwe_334() {
    let stdout = run_explain("CWE-334");
    assert_explainability_fields(&stdout, "CWE-334", "fixture-only");
    assert!(
        stdout.contains("--profile all"),
        "fixture-only must document --profile all:\n{stdout}"
    );
    assert!(
        stdout.contains("not production-certified"),
        "fixture-only must say not production-certified:\n{stdout}"
    );
    assert!(
        stdout.contains("quarantined"),
        "fixture-only must report quarantine:\n{stdout}"
    );
}

#[test]
fn cli_explain_reserved_bp_63() {
    let stdout = run_explain("BP-63");
    assert_explainability_fields(&stdout, "BP-63", "reserved");
    assert!(stdout.contains("quarantined"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("advisory") || stdout.contains("incomplete"),
        "reserved should note advisory/incomplete:\n{stdout}"
    );
}

#[test]
fn cli_explain_flag_alias_matches_subcommand() {
    let exe = env!("CARGO_BIN_EXE_codehound");
    let via_flag = Command::new(exe)
        .args(["--explain", "CWE-334"])
        .output()
        .expect("run --explain");
    let via_sub = Command::new(exe)
        .args(["rules", "--explain", "CWE-334"])
        .output()
        .expect("run rules --explain");
    assert!(via_flag.status.success());
    assert!(via_sub.status.success());
    let flag_out = String::from_utf8_lossy(&via_flag.stdout);
    let sub_out = String::from_utf8_lossy(&via_sub.stdout);
    assert_eq!(
        flag_out, sub_out,
        "--explain and rules --explain must match"
    );
}

#[test]
fn cli_list_rules_includes_maturity_tag() {
    let exe = env!("CARGO_BIN_EXE_codehound");
    let run = Command::new(exe)
        .args(["rules", "--category", "security"])
        .output()
        .expect("run rules --category security");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "stdout:\n{stdout}");
    assert!(
        stdout.contains("[taint-core]") || stdout.contains("[fixture-only]"),
        "list should tag maturity:\n{stdout}"
    );
    assert!(stdout.contains("CWE-"), "stdout:\n{stdout}");
}
