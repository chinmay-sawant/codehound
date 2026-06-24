use std::collections::BTreeSet;

use slopguard::core::LanguageId;
use slopguard::engine::Registry;

fn registry_toml_perf_ids() -> BTreeSet<String> {
    let text = std::fs::read_to_string("src/lang/go/detectors/perf/registry.toml")
        .expect("read PERF registry");
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("perf = "))
        .map(|value| format!("PERF-{}", value.trim()))
        .collect()
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
