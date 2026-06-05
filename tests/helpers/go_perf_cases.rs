#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub fn discover_go_perf_cases() -> Vec<u32> {
    let dir = Path::new("tests/fixtures/go/perf");
    let vulnerable = collect_cases_with_suffix(&dir, "-vulnerable.txt");
    let safe = collect_cases_with_suffix(&dir, "-safe.txt");

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

fn collect_cases_with_suffix(dir: &Path, suffix: &str) -> BTreeSet<String> {
    let mut cases = BTreeSet::new();

    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
        let path = entry
            .unwrap_or_else(|e| panic!("read_dir entry {}: {e}", dir.display()))
            .path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_else(|| panic!("non-utf8 fixture path: {}", path.display()));

        if let Some(case) = name.strip_suffix(suffix) {
            cases.insert(case.to_string());
        }
    }

    cases
}
