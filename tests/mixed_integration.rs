//! Mixed-repo: materialize all `.txt` fixtures then scan generated sources.

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn materialized_fixtures_detect_python_rules() {
    helpers::assert_mixed_txt_fixtures("tests/fixtures", &[], &["SLOP101"]);
}
