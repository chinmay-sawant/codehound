use slopguard::engine::AnalysisResult;
use slopguard::reporting::text::{TextOptions, write_with_options};

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn empty_result_renders_summary() {
    let r = AnalysisResult::default();
    let mut out = Vec::new();
    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(rendered.contains("no slop detected"), "{rendered}");
}

#[test]
fn finding_with_cwe_renders() {
    let r = helpers::reporting::one_finding_result();
    let mut out = Vec::new();
    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(rendered.contains("CWE-89"), "{rendered}");
    assert!(rendered.contains("1 finding"), "{rendered}");
}

#[test]
fn text_output_hides_fingerprint_by_default() {
    let r = helpers::reporting::one_finding_result();
    let mut out = Vec::new();

    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(!rendered.contains("fingerprint:"), "{rendered}");
    assert!(
        !rendered.contains("slopguard:1:CWE-89:a.go:1:1"),
        "{rendered}"
    );
}

#[test]
fn text_output_can_show_fingerprint() {
    let r = helpers::reporting::one_finding_result();
    let mut out = Vec::new();

    write_with_options(
        &mut out,
        &r,
        TextOptions {
            show_fingerprint: true,
            ..TextOptions::default()
        },
    )
    .unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(
        rendered.contains("fingerprint: slopguard:1:CWE-89:a.go:1:1"),
        "{rendered}"
    );
}
