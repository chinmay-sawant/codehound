#[path = "helpers/mod.rs"]
mod helpers;
use helpers::cache::{finding, unique_temp_root};

use slopguard::engine::{BASELINE_FILE_NAME, Baseline};

#[test]
fn baseline_from_findings_groups_entries_by_rule() {
    let baseline = Baseline::from_findings(&[
        finding("CWE-22", "a.go", 1, 2),
        finding("CWE-89", "b.go", 3, 4),
    ]);

    assert_eq!(baseline.version, "1");
    assert_eq!(baseline.entry_count(), 2);
    assert_eq!(
        baseline.entries["CWE-22"][0].fingerprint,
        "slopguard:1:CWE-22:a.go:1:2"
    );
    assert_eq!(
        baseline.entries["CWE-89"][0].fingerprint,
        "slopguard:1:CWE-89:b.go:3:4"
    );
}

#[test]
fn baseline_contains_matches_exact_fingerprint() {
    let baseline = Baseline::from_findings(&[finding("CWE-22", "a.go", 1, 2)]);

    assert!(baseline.contains("CWE-22", "a.go", 1, 2));
    assert!(!baseline.contains("CWE-22", "a.go", 1, 3));
    assert!(!baseline.contains("CWE-22", "b.go", 1, 2));
    assert!(!baseline.contains("CWE-89", "a.go", 1, 2));
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
    assert!(loaded.contains("CWE-22", "a.go", 1, 2));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn empty_baseline_contains_nothing() {
    let baseline = Baseline::from_findings(&[]);

    assert_eq!(baseline.entry_count(), 0);
    assert!(!baseline.contains("CWE-22", "a.go", 1, 2));
}
