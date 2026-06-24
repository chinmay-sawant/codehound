use std::borrow::Cow;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use slopguard::engine::{BASELINE_FILE_NAME, Baseline, discover_baseline};
use slopguard::rules::{Finding, LineCol, Severity};

fn unique_temp_root(test_name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("slopguard-{test_name}-{unique}"))
}

fn finding(rule_id: &'static str, file: &str, line: usize, column: usize) -> Finding {
    Finding::new(
        rule_id,
        "title",
        file,
        LineCol { line, column },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    )
}

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

#[test]
fn discover_baseline_walks_up_to_git_root() {
    let root = unique_temp_root("baseline-discovery");
    let nested = root.join("pkg/service");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    let baseline_path = root.join(BASELINE_FILE_NAME);
    std::fs::write(&baseline_path, "{}").unwrap();

    assert_eq!(discover_baseline(&nested), Some(baseline_path));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn baseline_schema_file_is_valid_json_and_covers_known_fields() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("slopguard-baseline.schema.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse schema: {e}"));

    for field in ["version", "generated_at", "tool_version", "entries"] {
        assert!(
            v.pointer(&format!("/properties/{field}")).is_some(),
            "baseline schema must describe `{field}`"
        );
    }
    assert_eq!(
        v.pointer("/additionalProperties"),
        Some(&serde_json::Value::Bool(false))
    );
    assert_eq!(
        v.pointer("/properties/entries/additionalProperties/items/properties/fingerprint/pattern"),
        Some(&serde_json::Value::String("^slopguard:1:".to_string()))
    );
}

#[test]
fn large_baseline_loads_and_filters_under_target() {
    let root = unique_temp_root("baseline-large");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(BASELINE_FILE_NAME);

    let baseline_findings: Vec<Finding> = (0..10_000)
        .map(|i| finding("CWE-78", &format!("pkg/file_{i}.go"), i + 1, 7))
        .collect();
    Baseline::from_findings(&baseline_findings)
        .to_file(&path)
        .unwrap();

    let mut findings_to_filter: Vec<Finding> = (0..10_000)
        .map(|i| finding("CWE-78", &format!("pkg/file_{i}.go"), i + 1, 7))
        .chain((0..100).map(|i| finding("CWE-78", &format!("pkg/new_{i}.go"), i + 1, 7)))
        .collect();

    let started = Instant::now();
    let baseline = Baseline::from_file(&path).unwrap();
    findings_to_filter.retain(|finding| !baseline.contains_finding(finding));
    let elapsed = started.elapsed();

    assert_eq!(baseline.entry_count(), 10_000);
    assert_eq!(findings_to_filter.len(), 100);
    assert!(
        elapsed.as_millis() < 200,
        "large baseline load/filter took {elapsed:?}, expected <200ms"
    );

    std::fs::remove_dir_all(root).unwrap();
}
