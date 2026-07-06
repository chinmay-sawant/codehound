#![allow(dead_code)]

use std::path::Path;

pub fn discover_go_perf_cases() -> Vec<u32> {
    let dir = Path::new("tests/fixtures/go/perf");
    let vulnerable = super::helpers::collect_cases_with_suffix(dir, "-vulnerable.txt");
    let safe = super::helpers::collect_cases_with_suffix(dir, "-safe.txt");

    assert_eq!(
        vulnerable, safe,
        "Go PERF vulnerable/safe fixture sets drifted"
    );

    let mut cases: Vec<u32> = vulnerable
        .into_iter()
        .map(|c| {
            c.strip_prefix("PERF-")
                .unwrap_or_else(|| panic!("invalid PERF id: {c}"))
                .parse::<u32>()
                .unwrap_or_else(|e| panic!("invalid PERF number in {c}: {e}"))
        })
        .collect();
    cases.sort_unstable();
    cases
}

pub fn fixture_path(perf_id: u32, vulnerable: bool) -> String {
    let suffix = if vulnerable { "vulnerable" } else { "safe" };
    format!("tests/fixtures/go/perf/PERF-{perf_id:03}-{suffix}.txt")
}
