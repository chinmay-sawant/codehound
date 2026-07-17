//! Inter-procedural taint tracking integration tests.
//!
//! Registered inter-procedural fixtures run with the enabled taint analyzer.

#[path = "helpers/go_taint_cases.rs"]
mod go_taint_cases;
#[path = "helpers/mod.rs"]
mod helpers;

use std::sync::OnceLock;

use codehound::core::ScanContext;
use codehound::engine::Analyzer;

static TAINT_ANALYZER: OnceLock<Analyzer> = OnceLock::new();

fn taint_analyzer() -> &'static Analyzer {
    TAINT_ANALYZER.get_or_init(|| {
        let ctx = ScanContext {
            taint_enabled: true,
            ..ScanContext::default()
        }
        .with_taint_max_depth(4);
        Analyzer::builder().scan_context(ctx).build()
    })
}

/// Channel/goroutine cases are deliberately absent until that flow model exists.
const DEFERRED: &[&str] = &[];

#[test]
fn inter_procedural_taint_fixtures_fire_vulnerable_and_silence_safe() {
    let cases = go_taint_cases::discover_inter_procedural_cases();
    let analyzer = taint_analyzer();
    let mut failures: Vec<String> = Vec::new();

    for ip_id in &cases {
        if DEFERRED.contains(&ip_id.as_str()) {
            continue;
        }
        let vulnerable = format!("tests/fixtures/go/taint/{ip_id}-vulnerable.txt");
        let safe = format!("tests/fixtures/go/taint/{ip_id}-safe.txt");

        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let vuln_path = helpers::assert_fixture_materializes(&vulnerable);
            let safe_path = helpers::assert_fixture_materializes(&safe);

            let vuln_result = analyzer.analyze_paths(&[&vuln_path], None).unwrap();
            assert!(
                vuln_result.findings.iter().any(|f| f.rule_id == "CWE-22"),
                "{ip_id} vulnerable fixture should fire CWE-22"
            );

            let safe_result = analyzer.analyze_paths(&[&safe_path], None).unwrap();
            assert!(
                !safe_result.findings.iter().any(|f| f.rule_id == "CWE-22"),
                "{ip_id} safe fixture should be silent, got {:?}",
                safe_result.findings
            );
        })) {
            failures.push(format!("{ip_id}: {e:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} inter-procedural fixtures failed: {failures:#?}",
        failures.len(),
        cases.len() * 2,
    );
}

#[test]
fn inter_procedural_taint_fixture_inventory_is_sorted_and_contiguous() {
    let cases = go_taint_cases::discover_inter_procedural_cases();
    assert!(!cases.is_empty(), "expected at least one IP fixture");

    let eligible: Vec<_> = cases
        .iter()
        .filter(|c| !DEFERRED.contains(&c.as_str()))
        .collect();
    let mut prev = 0u32;
    for ip_id in &eligible {
        let Some(num_str) = ip_id.strip_prefix("IP-") else {
            panic!("fixture id must start with IP-: {ip_id}");
        };
        let num: u32 = num_str.parse().expect("IP-XXX number parse");
        assert_eq!(
            *ip_id,
            &format!("IP-{num:03}"),
            "fixture id must be zero-padded: {ip_id}"
        );
        assert!(
            num > prev,
            "fixture ids must be strictly increasing: IP-{prev:03} then {num} ({ip_id})"
        );
        prev = num;
    }
}
