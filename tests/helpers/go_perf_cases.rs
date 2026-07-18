#![allow(dead_code)]

use std::cmp::Ordering;
use std::path::Path;

/// Discover PERF fixture cases from `tests/fixtures/go/perf`.
///
/// Base cases use zero-padded ids (`PERF-038`). Named variants append a
/// kebab suffix after the id (`PERF-038-done`, `PERF-114-interface`), matching
/// the BP fixture layout (`BP-5-variant`, `BP-37-map`).
pub fn discover_go_perf_cases() -> Vec<String> {
    let dir = Path::new("tests/fixtures/go/perf");
    let vulnerable = super::helpers::collect_cases_with_suffix(dir, "-vulnerable.txt");
    let safe = super::helpers::collect_cases_with_suffix(dir, "-safe.txt");

    assert_eq!(
        vulnerable, safe,
        "Go PERF vulnerable/safe fixture sets drifted"
    );

    let mut cases: Vec<String> = vulnerable.into_iter().collect();
    cases.sort_by(|left, right| compare_perf_case_names(left, right));
    cases
}

/// Rule id emitted by the analyzer for a fixture case.
///
/// `PERF-038` and `PERF-038-done` both map to `PERF-38` (no zero-padding in
/// rule ids). `PERF-114-interface` maps to `PERF-114`.
pub fn expected_rule_id(case: &str) -> String {
    let Some((number, _)) = parse_perf_case_name(case) else {
        panic!("invalid PERF fixture case: {case}");
    };
    format!("PERF-{number}")
}

pub fn fixture_path(case: &str, vulnerable: bool) -> String {
    let suffix = if vulnerable { "vulnerable" } else { "safe" };
    format!("tests/fixtures/go/perf/{case}-{suffix}.txt")
}

pub fn is_sorted_and_deduplicated(cases: &[String]) -> bool {
    cases
        .windows(2)
        .all(|window| compare_perf_case_names(&window[0], &window[1]).is_lt())
}

fn compare_perf_case_names(left: &str, right: &str) -> Ordering {
    match (parse_perf_case_name(left), parse_perf_case_name(right)) {
        (Some(left_parts), Some(right_parts)) => {
            left_parts.cmp(&right_parts).then_with(|| left.cmp(right))
        }
        _ => left.cmp(right),
    }
}

/// `(rule_number, optional_variant_tail)` for `PERF-038` / `PERF-038-done`.
fn parse_perf_case_name(case: &str) -> Option<(u32, Option<&str>)> {
    let rest = case.strip_prefix("PERF-")?;
    let (number, tail) = rest
        .split_once('-')
        .map_or((rest, None), |(number, tail)| (number, Some(tail)));
    Some((number.parse().ok()?, tail))
}
