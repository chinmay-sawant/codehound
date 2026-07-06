#![allow(dead_code)]

use std::cmp::Ordering;
use std::path::Path;

pub fn discover_go_bp_cases() -> Vec<String> {
    let dir = Path::new("tests/fixtures/go/bad_practices");
    let vulnerable = super::helpers::collect_cases_with_suffix(dir, "-vulnerable.txt");
    let safe = super::helpers::collect_cases_with_suffix(dir, "-safe.txt");

    assert_eq!(
        vulnerable, safe,
        "Go BP vulnerable/safe fixture sets drifted"
    );

    let mut cases: Vec<String> = vulnerable.into_iter().collect();
    cases.sort_by(|left, right| compare_bp_case_names(left, right));
    cases
}

pub fn expected_rule_id(case: &str) -> String {
    let Some((prefix, rest)) = case.split_once('-') else {
        panic!("invalid BP fixture case: {case}");
    };
    assert_eq!(prefix, "BP", "invalid BP fixture case prefix: {case}");
    let number = rest
        .split('-')
        .next()
        .unwrap_or_else(|| panic!("invalid BP fixture case number: {case}"));
    format!("BP-{number}")
}

pub fn fixture_path(case: &str, vulnerable: bool) -> String {
    let suffix = if vulnerable { "vulnerable" } else { "safe" };
    format!("tests/fixtures/go/bad_practices/{case}-{suffix}.txt")
}

pub fn is_sorted_and_deduplicated(cases: &[String]) -> bool {
    cases
        .windows(2)
        .all(|window| compare_bp_case_names(&window[0], &window[1]).is_lt())
}

fn compare_bp_case_names(left: &str, right: &str) -> Ordering {
    match (parse_bp_case_name(left), parse_bp_case_name(right)) {
        (Some(left_parts), Some(right_parts)) => {
            left_parts.cmp(&right_parts).then_with(|| left.cmp(right))
        }
        _ => left.cmp(right),
    }
}

fn parse_bp_case_name(case: &str) -> Option<(u32, Option<&str>)> {
    let rest = case.strip_prefix("BP-")?;
    let (number, tail) = rest
        .split_once('-')
        .map_or((rest, None), |(number, tail)| (number, Some(tail)));
    Some((number.parse().ok()?, tail))
}
