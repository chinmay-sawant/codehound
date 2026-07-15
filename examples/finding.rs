use std::borrow::Cow;

use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

fn main() {
    let location = LineCol::try_new(3, 5).expect("non-zero source location");
    let finding = Finding::new(FindingInputs::new(
        "CWE-89",
        "SQL injection",
        "src/handler.go",
        location,
        "query uses untrusted input",
        Severity::High,
        Cow::Owned(Vec::new()),
    ))
    .with_confidence_checked(0.9)
    .expect("confidence is within 0..=1");

    assert_eq!(finding.line, 3);
    assert_eq!(finding.severity, Severity::High);
}
