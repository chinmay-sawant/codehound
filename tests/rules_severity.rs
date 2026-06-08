use slopguard::rules::Severity;

#[test]
fn as_str_matches_variant() {
    assert_eq!(Severity::Info.as_str(), "info");
    assert_eq!(Severity::Low.as_str(), "low");
    assert_eq!(Severity::Medium.as_str(), "medium");
    assert_eq!(Severity::High.as_str(), "high");
    assert_eq!(Severity::Critical.as_str(), "critical");
}

#[test]
fn display_matches_as_str() {
    for s in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        assert_eq!(format!("{s}"), s.as_str());
    }
}

#[test]
fn is_failure_threshold_matches_medium() {
    assert!(!Severity::Info.is_failure());
    assert!(!Severity::Low.is_failure());
    assert!(Severity::Medium.is_failure());
    assert!(Severity::High.is_failure());
    assert!(Severity::Critical.is_failure());
}

#[test]
fn ordering_is_info_lt_low_lt_medium_lt_high_lt_critical() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn serde_emits_lowercase() {
    let s = serde_json::to_string(&Severity::High).unwrap();
    assert_eq!(s, "\"high\"");
}
