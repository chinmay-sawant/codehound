#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::Path;

pub fn discover_go_cwe_cases() -> Vec<String> {
    let frameworks = collect_suite_cases("frameworks");
    let stdlib = collect_suite_cases("stdlib");

    assert_eq!(
        frameworks, stdlib,
        "framework and stdlib Go fixture inventories drifted"
    );

    let mut cases: Vec<_> = frameworks.into_iter().collect();
    cases.sort_by_key(|cwe| parse_cwe_number(cwe));
    cases
}

pub fn fixture_path(suite: &str, cwe: &str, vulnerable: bool) -> String {
    let suffix = if vulnerable { "vulnerable" } else { "safe" };
    format!("tests/fixtures/go/{suite}/{cwe}-{suffix}.txt")
}

pub fn parse_cwe_number(cwe: &str) -> u32 {
    cwe.strip_prefix("CWE-")
        .unwrap_or_else(|| panic!("invalid CWE id: {cwe}"))
        .parse::<u32>()
        .unwrap_or_else(|e| panic!("invalid CWE number in {cwe}: {e}"))
}

fn collect_cases_with_suffix(dir: &Path, suffix: &str) -> BTreeSet<String> {
    let mut cases = BTreeSet::new();
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
    {
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

fn collect_suite_cases(suite: &str) -> BTreeSet<String> {
    let dir = Path::new("tests/fixtures/go").join(suite);
    let vulnerable = collect_cases_with_suffix(&dir, "-vulnerable.txt");
    let safe = collect_cases_with_suffix(&dir, "-safe.txt");

    assert_eq!(
        vulnerable, safe,
        "{suite} vulnerable/safe fixture sets drifted"
    );

    vulnerable
}
