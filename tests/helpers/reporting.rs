//! Shared test helpers for reporting tests.

use slopguard::engine::AnalysisResult;
use slopguard::rules::Finding;

pub fn sample_result(findings: Vec<Finding>) -> AnalysisResult {
    let suppressed_count = findings.iter().filter(|f| f.suppressed).count();
    AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings,
        errors: vec![],
        suppressed_count,
        stats: None,
    }
}
