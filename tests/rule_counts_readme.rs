//! Keep README rule counts honest against the live registry.

use codehound::engine::Registry;

#[test]
fn readme_rule_counts_match_registry() {
    let registry = Registry::default();
    let mut cwe = 0usize;
    let mut perf = 0usize;
    let mut bp = 0usize;
    let mut other = 0usize;

    for det in registry.detectors() {
        for id in det.rule_ids() {
            if id.starts_with("CWE-") {
                cwe += 1;
            } else if id.starts_with("PERF-") {
                perf += 1;
            } else if id.starts_with("BP-") {
                bp += 1;
            } else {
                other += 1;
            }
        }
    }

    // README claims (see README.md feature bullets). Update both together.
    // Default features are Go-only (ADR 0005); Python SLOP101 is opt-in via
    // `--features python` and is not counted here.
    assert_eq!(cwe, 175, "CWE count drifted; update README.md");
    assert_eq!(perf, 239, "PERF count drifted; update README.md");
    assert_eq!(bp, 136, "BP count drifted; update README.md");
    let expected_other = usize::from(cfg!(feature = "python"));
    assert_eq!(
        other, expected_other,
        "unexpected non-Go rules for enabled features; update README.md / features"
    );
}
