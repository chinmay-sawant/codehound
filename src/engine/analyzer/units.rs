//! `Analyzer::analyze_units`: per-unit analysis using pre-parsed input.

use crate::core::ParsedUnit;
use crate::engine::walk::analyze_parsed_unit_with_context;
use crate::rules::Finding;

use super::scan::sort_findings;
use super::types::Analyzer;

impl Analyzer {
    pub fn analyze_units(&self, units: &[ParsedUnit]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for unit in units {
            findings.extend(analyze_parsed_unit_with_context(
                &self.registry,
                &self.ctx,
                unit,
            ));
        }
        sort_findings(&mut findings);
        findings
    }
}
