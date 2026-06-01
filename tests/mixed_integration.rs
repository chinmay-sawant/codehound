//! Mixed-repo: materialize all `.txt` fixtures then scan generated sources.

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn materialized_fixtures_detect_go_and_python() {
    helpers::assert_mixed_txt_fixtures("tests/fixtures", &["SLOP001"], &["SLOP101"]);
}
