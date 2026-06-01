//! Python integration tests — must use `tests/fixtures/python/` only.

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn python_sample_fires_slop101() {
    helpers::assert_fixture_rules("tests/fixtures/python/sample.txt", &["SLOP101"]);
}
