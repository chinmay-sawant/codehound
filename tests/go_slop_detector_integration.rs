//! Go detector regression tests for non-CWE SLOP rules.

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn map_alloc_in_loop_fixture_still_fires() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/sample.txt", &["SLOP001"]);
}
