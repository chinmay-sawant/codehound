//! Smoke test: verify the clean Go file triggers zero false positives
//! when scanned with all shipped detectors (PERF + BP + CWE).

use slopguard::engine::Analyzer;

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn clean_go_file_produces_zero_findings_across_all_detectors() {
    let analyzer = Analyzer::builder().with_default_filter().build();
    let txt = "tests/fixtures/go/perf_real_world/clean_go_file.txt";
    let source = helpers::assert_fixture_materializes(txt);
    let result = analyzer
        .analyze_paths(&[&source], None)
        .expect("clean file should scan without errors");
    assert!(
        result.findings.is_empty(),
        "clean Go file produced {} false positives: {:#?}",
        result.findings.len(),
        result.findings,
    );
}
