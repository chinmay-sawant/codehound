use slopguard::reporting::sarif::render_to_string;

#[path = "helpers/mod.rs"]
mod helpers;

fn iso8601_from_secs(secs: u64) -> String {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[test]
fn driver_fields_are_populated() {
    let log = render_to_string(&helpers::reporting::sample_result());
    assert!(log.contains("\"informationUri\""), "got: {log}");
    assert!(log.contains("\"semanticVersion\""), "got: {log}");
    assert!(log.contains("\"name\": \"slopguard\""), "got: {log}");
}

#[test]
fn rules_array_is_sorted_alphabetically() {
    let log = render_to_string(&helpers::reporting::sample_result());
    let i22 = log.find("\"CWE-22\"").expect("CWE-22");
    let i89 = log.find("\"CWE-89\"").expect("CWE-89");
    assert!(i22 < i89, "CWE-22 should appear before CWE-89, got: {log}");
}

#[test]
fn results_have_rule_index_pointing_into_rules() {
    let log = render_to_string(&helpers::reporting::sample_result());
    assert!(log.contains("\"ruleIndex\""), "got: {log}");
}

#[test]
fn results_have_partial_fingerprints() {
    let log = render_to_string(&helpers::reporting::sample_result());
    assert!(
        log.contains("\"partialFingerprints\""),
        "missing partialFingerprints, got: {log}"
    );
    assert!(
        log.contains("\"slopguard/v1\": \"slopguard:1:CWE-22:a.go:1:1\""),
        "missing canonical fingerprint, got: {log}"
    );
}

#[test]
fn results_have_security_severity_in_properties() {
    let log = render_to_string(&helpers::reporting::sample_result());
    assert!(log.contains("\"security-severity\""), "got: {log}");
    assert!(log.contains("\"tags\""), "got: {log}");
}

#[test]
fn iso8601_format_is_correct() {
    let s = iso8601_from_secs(1_704_067_200);
    assert_eq!(s, "2024-01-01T00:00:00Z");
}
