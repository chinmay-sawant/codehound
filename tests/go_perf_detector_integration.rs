//! Go PERF detector regression tests.
//!
//! Fixture inventory is discovered from `tests/fixtures/go/perf` so the test
//! suite does not need a second hand-maintained list of PERF ids.

#[path = "helpers/go_perf_cases.rs"]
mod go_perf_cases;
#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn go_perf_fixtures_fire_vulnerable_and_silence_safe() {
    let cases = go_perf_cases::discover_go_perf_cases();
    let mut failures: Vec<String> = Vec::new();

    for perf_id in &cases {
        let vulnerable = go_perf_cases::fixture_path(*perf_id, true);
        let safe = go_perf_cases::fixture_path(*perf_id, false);
        let rule = format!("PERF-{perf_id}");
        if let Err(e) = std::panic::catch_unwind(|| {
            helpers::assert_fixture_rules(&vulnerable, &[rule.as_str()]);
            helpers::assert_fixture_rules(&safe, &[]);
        }) {
            failures.push(format!("PERF-{perf_id}: {e:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} PERF fixtures failed: {failures:#?}",
        failures.len(),
        cases.len() * 2,
    );
}

#[test]
fn go_perf_fixture_inventory_is_sorted_and_contiguous() {
    let cases = go_perf_cases::discover_go_perf_cases();

    assert!(!cases.is_empty(), "expected at least one Go PERF fixture");

    let expected: Vec<u32> = (cases[0]..=*cases.last().unwrap()).collect();
    assert_eq!(
        cases, expected,
        "Go PERF fixture ids must be contiguous starting at {}",
        cases[0]
    );
}
