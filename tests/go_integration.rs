//! Go integration tests — must use `tests/fixtures/go/frameworks/` only.

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn go_sample_fires_slop001() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/sample.txt", &["SLOP001"]);
}
