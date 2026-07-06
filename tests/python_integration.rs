//! Python integration tests — must use `tests/fixtures/python/` only.

use slopguard::engine::Analyzer;

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn python_sample_fires_slop101() {
    let analyzer = Analyzer::builder().build();
    helpers::assert_fixture_rules("tests/fixtures/python/sample.txt", &["SLOP101"], &analyzer);
}

#[test]
fn python_safe_does_not_fire_slop101() {
    // Negative case: re.compile appears at module level and hoisted before a loop;
    // the SLOP101 rule must NOT fire. Empty required_rules asserts no CWE / SLOP
    // findings are emitted by the analyzer.
    let analyzer = Analyzer::builder().build();
    helpers::assert_fixture_rules("tests/fixtures/python/safe.txt", &[], &analyzer);
}
