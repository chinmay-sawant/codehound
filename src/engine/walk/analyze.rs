//! Run enabled detectors on an already-parsed unit.

use crate::core::{ParsedUnit, ScanContext};
use crate::engine::registry::Registry;
use crate::engine::timing::TimingCollector;
use crate::rules::Finding;

/// Retain findings allowed by the scan context and apply per-rule overrides.
pub(crate) fn filter_findings(ctx: &ScanContext, findings: &mut Vec<Finding>) {
    findings.retain(|f| ctx.allows(f.rule_id));
    for f in findings.iter_mut() {
        ctx.apply_finding_overrides(f);
    }
}

/// Run enabled detectors on an already-parsed unit.
///
/// Returns the findings and the number of detector invocations that actually
/// executed (used for scan statistics). Per-detector timing is recorded in
/// the caller-owned collector.
pub(crate) fn analyze_parsed_unit(
    registry: &Registry,
    ctx: &ScanContext,
    unit: &ParsedUnit,
    timing: &mut TimingCollector,
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut rules_executed = 0;
    for &idx in registry.detector_indices(unit.language) {
        let Some(det) = registry.detector(idx) else {
            continue;
        };
        if !det.rule_ids().iter().any(|id| ctx.allows(id)) {
            continue;
        }
        rules_executed += 1;
        if timing.is_enabled() {
            let name = det.rule_ids().first().copied().unwrap_or("detector");
            let span = timing.start(name);
            det.run(ctx, unit, &mut findings);
            timing.stop(span);
        } else {
            det.run(ctx, unit, &mut findings);
        }
    }
    (findings, rules_executed)
}
