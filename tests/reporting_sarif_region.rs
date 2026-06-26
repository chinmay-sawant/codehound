use slopguard::reporting::sarif::render_to_string;

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn end_line_end_column_byte_offset_optional() {
    let mut r = helpers::reporting::sample_result();
    r.findings[0].end_line = Some(2);
    r.findings[0].end_column = Some(8);
    r.findings[0].byte_offset = Some(42);
    r.findings[0].byte_length = Some(7);
    let log = render_to_string(&r);
    assert!(log.contains("\"endLine\": 2"), "got: {log}");
    assert!(log.contains("\"endColumn\": 8"), "got: {log}");
    assert!(log.contains("\"byteOffset\": 42"), "got: {log}");
    assert!(log.contains("\"byteLength\": 7"), "got: {log}");
}

#[test]
fn region_end_fields_absent_when_unset() {
    let r = helpers::reporting::sample_result();
    let log = render_to_string(&r);
    assert!(!log.contains("endLine"), "got: {log}");
    assert!(!log.contains("byteOffset"), "got: {log}");
}

#[test]
fn rank_is_absent_when_confidence_unset() {
    let log = render_to_string(&helpers::reporting::sample_result());
    assert!(!log.contains("\"rank\""), "got: {log}");
}

#[test]
fn rank_maps_confidence_to_sarif_scale() {
    let mut r = helpers::reporting::sample_result();
    r.findings[0].confidence = Some(0.75);

    let log = render_to_string(&r);
    assert!(log.contains("\"rank\": 75"), "got: {log}");
}

#[test]
fn suppressions_are_absent_when_not_suppressed() {
    let log = render_to_string(&helpers::reporting::sample_result());
    assert!(!log.contains("\"suppressions\""), "got: {log}");
}

#[test]
fn suppressions_present_when_finding_suppressed() {
    let mut r = helpers::reporting::sample_result();
    r.findings[0].suppressed = true;

    let log = render_to_string(&r);
    assert!(log.contains("\"suppressions\""), "got: {log}");
    assert!(log.contains("\"kind\": \"external\""), "got: {log}");
}
