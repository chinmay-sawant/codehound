use slopguard::reporting::text::{TextOptions, write_with_options};

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn text_output_shows_metadata_without_raw_evidence_by_default() {
    let r = helpers::reporting::one_structured_finding_result();
    let mut out = Vec::new();

    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(rendered.contains("confidence: 0.75"), "{rendered}");
    assert!(
        rendered.contains("tags: needs-review, heuristic"),
        "{rendered}"
    );
    assert!(rendered.contains("status: suppressed"), "{rendered}");
    assert!(!rendered.contains("evidence:"), "{rendered}");
    assert!(!rendered.contains("exec.Command"), "{rendered}");
}

#[test]
fn verbose_text_output_shows_evidence_summary() {
    let r = helpers::reporting::one_structured_finding_result();
    let mut out = Vec::new();

    write_with_options(
        &mut out,
        &r,
        TextOptions {
            verbose: true,
            ..TextOptions::default()
        },
    )
    .unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(
        rendered.contains("evidence: dangerous call `exec.Command` argument 0"),
        "{rendered}"
    );
}

#[test]
fn text_output_hides_full_confidence() {
    let mut r = helpers::reporting::one_finding_result();
    r.findings[0].confidence = Some(1.0);
    let mut out = Vec::new();

    write_with_options(&mut out, &r, TextOptions::default()).unwrap();
    let rendered = String::from_utf8(out).unwrap();

    assert!(!rendered.contains("confidence:"), "{rendered}");
}
