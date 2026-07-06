use std::collections::BTreeSet;

use slopguard::core::LanguageId;
use slopguard::engine::Registry;

fn registry_toml_perf_ids() -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let dir =
        std::fs::read_dir("src/lang/go/detectors/perf/registry").expect("read PERF registry dir");
    for entry in dir {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "toml") {
            let text = std::fs::read_to_string(&path).expect("read PERF registry file");
            ids.extend(
                text.lines()
                    .filter_map(|line| line.trim().strip_prefix("perf = "))
                    .map(|value| format!("PERF-{}", value.trim())),
            );
        }
    }
    ids
}

#[test]
fn generated_go_perf_dispatch_matches_registry_toml() {
    let expected = registry_toml_perf_ids();
    let registry = Registry::default();
    let actual: BTreeSet<String> = registry
        .detector_indices(LanguageId::Go)
        .iter()
        .flat_map(|idx| registry.detector(*idx).rule_ids().iter().copied())
        .filter(|id| id.starts_with("PERF-"))
        .map(str::to_string)
        .collect();

    assert_eq!(
        actual, expected,
        "generated Go PERF dispatch should match registry.toml"
    );
}
