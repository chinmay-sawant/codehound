#[path = "helpers/mod.rs"]
mod helpers;
use helpers::cache::finding;
use helpers::unique_temp_root;

use codehound::engine::{BASELINE_FILE_NAME, Baseline};
use codehound::rules::{Finding, FindingInputs, LineCol, Severity};
use std::borrow::Cow;

fn finding_msg(rule: &'static str, file: &str, line: usize, col: usize, msg: &str) -> Finding {
    Finding::new(FindingInputs::new(
        rule,
        "title",
        file,
        LineCol { line, column: col },
        msg,
        Severity::High,
        Cow::Borrowed(&[]),
    ))
}

#[test]
fn baseline_from_findings_groups_entries_by_rule() {
    let baseline = Baseline::from_findings(&[
        finding("CWE-22", "a.go", 1, 2),
        finding("CWE-89", "b.go", 3, 4),
    ]);

    assert_eq!(baseline.version, "1");
    assert_eq!(baseline.entry_count(), 2);
    assert!(
        baseline.entries["CWE-22"][0]
            .fingerprint
            .starts_with("codehound:2:CWE-22:a.go:")
    );
    assert!(
        baseline.entries["CWE-89"][0]
            .fingerprint
            .starts_with("codehound:2:CWE-89:b.go:")
    );
}

#[test]
fn baseline_fingerprint_is_message_stable_not_column() {
    // helpers::finding uses a fixed message, so column drift still matches via fingerprint.
    let baseline = Baseline::from_findings(&[finding("CWE-22", "a.go", 1, 2)]);
    assert!(baseline.contains_finding(&finding("CWE-22", "a.go", 1, 2)));
    assert!(
        baseline.contains_finding(&finding("CWE-22", "a.go", 1, 3)),
        "same rule/file/message should match across column drift"
    );
    assert!(!baseline.contains_finding(&finding("CWE-22", "b.go", 1, 2)));
    assert!(!baseline.contains_finding(&finding("CWE-89", "a.go", 1, 2)));
}

#[test]
fn baseline_different_message_does_not_match_fingerprint() {
    let baseline = Baseline::from_findings(&[finding_msg("CWE-22", "a.go", 1, 1, "msg-a")]);
    // Different message + different line → no fingerprint or location match.
    assert!(!baseline.contains_finding(&finding_msg("CWE-22", "a.go", 9, 1, "msg-b")));
    // Same location still matches via location pin even if message changes.
    assert!(baseline.contains_finding(&finding_msg("CWE-22", "a.go", 1, 1, "msg-b")));
}

#[test]
fn baseline_round_trips_to_file() {
    let root = unique_temp_root("baseline-round-trip");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(BASELINE_FILE_NAME);
    let baseline = Baseline::from_findings(&[finding("CWE-22", "a.go", 1, 2)]);

    baseline.to_file(&path).unwrap();
    let loaded = Baseline::from_file(&path).unwrap();

    assert_eq!(loaded.entry_count(), 1);
    assert!(loaded.contains_finding(&finding("CWE-22", "a.go", 1, 2)));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn empty_baseline_contains_nothing() {
    let baseline = Baseline::from_findings(&[]);

    assert_eq!(baseline.entry_count(), 0);
    assert!(!baseline.contains_finding(&finding("CWE-22", "a.go", 1, 2)));
}
