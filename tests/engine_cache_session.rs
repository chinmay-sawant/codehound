//! [`CacheSession`] exposes only scan-time cache operations.

use codehound::core::ScanContext;
use codehound::engine::{CacheLookup, CacheSession, CacheStore};
use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

#[test]
fn cache_session_delegates_lookup_and_flush() {
    let mut store = CacheStore::in_memory();
    let mut session = CacheSession::open(&mut store);
    assert!(matches!(
        session.lookup("missing.go", "abc"),
        CacheLookup::Miss
    ));
    session.flush().expect("ephemeral flush is a no-op");
}

#[test]
fn cache_session_put_and_invalidate_round_trip() {
    let mut store = CacheStore::in_memory();
    let mut session = CacheSession::open(&mut store);
    let finding = Finding::new(FindingInputs::new(
        "CWE-1",
        "t",
        "a.go",
        LineCol { line: 1, column: 1 },
        "m",
        Severity::Low,
        std::borrow::Cow::Borrowed(&[]),
    ));
    session
        .put("a.go", "hash1", &[], vec![finding], "2026-01-01T00:00:00Z")
        .expect("put");
    assert!(matches!(
        session.lookup("a.go", "hash1"),
        CacheLookup::Hit(_)
    ));
    session.invalidate_file("a.go");
    assert!(matches!(session.lookup("a.go", "hash1"), CacheLookup::Miss));
}

#[test]
fn scan_context_fingerprint_tracks_cached_finding_policy() {
    let baseline = ScanContext::default().rule_config_fingerprint();

    let show_ignored = ScanContext {
        show_ignored: true,
        ..ScanContext::default()
    };
    assert_ne!(baseline, show_ignored.rule_config_fingerprint());

    let taint_paths = ScanContext {
        taint_show_paths: true,
        ..ScanContext::default()
    };
    assert_ne!(baseline, taint_paths.rule_config_fingerprint());

    let bp_severity = ScanContext {
        bad_practice_severity: Some(Severity::Critical),
        ..ScanContext::default()
    };
    assert_ne!(baseline, bp_severity.rule_config_fingerprint());

    let mut overrides = ScanContext::default();
    overrides
        .severity_overrides
        .insert("CWE-89".to_string(), Severity::Low);
    assert_ne!(baseline, overrides.rule_config_fingerprint());

    let mut first_order = ScanContext::default();
    first_order
        .severity_overrides
        .insert("CWE-22".to_string(), Severity::High);
    first_order
        .severity_overrides
        .insert("CWE-89".to_string(), Severity::Low);
    let mut second_order = ScanContext::default();
    second_order
        .severity_overrides
        .insert("CWE-89".to_string(), Severity::Low);
    second_order
        .severity_overrides
        .insert("CWE-22".to_string(), Severity::High);
    assert_eq!(
        first_order.rule_config_fingerprint(),
        second_order.rule_config_fingerprint()
    );
}
