//! [`CacheSession`] exposes only scan-time cache operations.

use slopguard::engine::{CacheLookup, CacheSession, CacheStore};
use slopguard::rules::{Finding, FindingInputs, LineCol, Severity};

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
