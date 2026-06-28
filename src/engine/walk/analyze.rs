//! Run enabled detectors on an already-parsed unit.

use crate::core::{ParsedUnit, ScanContext};
use crate::engine::registry::Registry;
use crate::engine::timing::TimingCollector;
use crate::rules::Finding;

use super::scan_entry::attach_function_context;

/// Run enabled detectors on an already-parsed unit.
///
/// Returns the findings and the number of detector invocations that actually
/// executed (used for scan statistics).
pub fn analyze_parsed_unit(
    registry: &Registry,
    ctx: &ScanContext,
    unit: &ParsedUnit,
    timing: &mut TimingCollector,
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut rules_executed = 0;
    let collect_detector_timing = ctx.collect_stats();
    for &idx in registry.detector_indices(unit.language) {
        let det = registry.detector(idx);
        if !det.rule_ids().iter().any(|id| ctx.allows(id)) {
            continue;
        }
        rules_executed += 1;
        if collect_detector_timing {
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

/// Run detectors **and** attach function-context ranges for a single unit.
/// This is the right entry point when the parsed unit is still alive (no
/// re-parse needed) — used by [`Analyzer::analyze_units`].
pub fn analyze_parsed_unit_with_context(
    registry: &Registry,
    ctx: &ScanContext,
    unit: &ParsedUnit,
) -> Vec<Finding> {
    let mut timing = TimingCollector::new(false);
    let (mut findings, _rules) = analyze_parsed_unit(registry, ctx, unit, &mut timing);
    if let Some(plugin) = registry.plugin_for_id(unit.language) {
        attach_function_context(&mut findings, plugin, unit);
    }
    findings
}
