use slopguard::rules::Severity;

#[test]
fn as_str_matches_variant() {
    assert_eq!(Severity::Info.as_str(), "info");
    assert_eq!(Severity::Warning.as_str(), "warning");
    assert_eq!(Severity::High.as_str(), "high");
    assert_eq!(Severity::Critical.as_str(), "critical");
}

#[test]
fn display_matches_as_str() {
    for s in [
        Severity::Info,
        Severity::Warning,
        Severity::High,
        Severity::Critical,
    ] {
        assert_eq!(format!("{s}"), s.as_str());
    }
}

#[test]
fn is_failure_threshold_matches_warning() {
    assert!(!Severity::Info.is_failure());
    assert!(Severity::Warning.is_failure());
    assert!(Severity::High.is_failure());
    assert!(Severity::Critical.is_failure());
}

#[test]
fn ordering_is_info_lt_warning_lt_high_lt_critical() {
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn serde_emits_lowercase() {
    let s = serde_json::to_string(&Severity::High).unwrap();
    assert_eq!(s, "\"high\"");
}
