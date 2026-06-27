#[path = "helpers/mod.rs"]
mod helpers;

use insta::assert_snapshot;
use slopguard::reporting::text::{TextOptions, write_with_options};

#[test]
fn text_summary_snapshot_is_stable() {
    let sample = helpers::reporting::sample_result();
    let mut buf = Vec::new();
    write_with_options(
        &mut buf,
        &sample,
        TextOptions {
            suppress_snippet: true,
            ..TextOptions::default()
        },
    )
    .unwrap();
    let s = String::from_utf8(buf).unwrap();
    assert_snapshot!("text_summary", s);
}
