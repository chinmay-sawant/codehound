//! Analysis output container.

use crate::rules::Finding;

/// Findings from a scan run.
#[derive(Debug, Default, Clone)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
}

impl AnalysisResult {
    pub fn should_fail(&self, policy: crate::core::FailPolicy) -> bool {
        self.findings.iter().any(|f| policy.should_fail(f.severity))
    }
}
