//! Mixed-repo: materialize all `.txt` fixtures then scan generated sources.

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
#[cfg(feature = "python")]
fn materialized_fixtures_detect_python_rules() {
    helpers::assert_mixed_txt_fixtures("tests/fixtures", &[], &["SLOP101"]);
}

#[test]
#[cfg(not(feature = "python"))]
fn materialized_fixtures_scan_without_python_feature() {
    // Default build is Go-only (ADR 0005); mixed tree should still scan cleanly.
    helpers::assert_mixed_txt_fixtures("tests/fixtures", &[], &[]);
}
