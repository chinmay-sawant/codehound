//! Smoke test mirroring the `lib.rs` quick-start example.

use codehound::core::ScanContext;
use codehound::engine::prelude::*;

#[test]
fn library_quick_start_analyzes_a_file() {
    let registry = Registry::default();
    let config = CodehoundConfig::default();
    let filter = resolve_language_filter(None, Some(&config), &registry).unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .language_filter(filter)
        .build();

    let result = analyzer.analyze_paths(&["src/lib.rs"], None).unwrap();
    assert!(
        result.errors.is_empty(),
        "unexpected scan errors: {:?}",
        result.errors
    );
}
