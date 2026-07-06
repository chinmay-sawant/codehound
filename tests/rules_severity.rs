use codehound::rules::Severity;

#[test]
fn severity_variants_are_consistent() {
    for (sev, as_str, is_failure) in [
        (Severity::Info, "info", false),
        (Severity::Low, "low", false),
        (Severity::Medium, "medium", true),
        (Severity::High, "high", true),
        (Severity::Critical, "critical", true),
    ] {
        assert_eq!(sev.as_str(), as_str);
        assert_eq!(format!("{sev}"), as_str);
        assert_eq!(sev.is_failure(), is_failure);
    }
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
    let s = serde_json::to_string(&Severity::High).unwrap();
    assert_eq!(s, "\"high\"");
}
