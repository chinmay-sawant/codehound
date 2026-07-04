#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::Path;

pub fn discover_inter_procedural_cases() -> Vec<String> {
    let taint_dir = Path::new("tests/fixtures/go/taint");
    let vulnerable = collect_cases_with_suffix(taint_dir, "-vulnerable.txt");
    let safe = collect_cases_with_suffix(taint_dir, "-safe.txt");

    assert_eq!(
        vulnerable, safe,
        "inter-procedural vulnerable/safe fixture sets drifted"
    );

    let cases: Vec<_> = vulnerable
        .into_iter()
        .filter(|id| id.starts_with("IP-"))
        .collect();
    cases
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
