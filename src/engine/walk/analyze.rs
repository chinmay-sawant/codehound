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
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_detector(det, ctx, unit, &mut findings, timing);
        }));
        if let Err(payload) = result {
            reset_detector_after_panic(det);
            std::panic::resume_unwind(payload);
        }
    }
    (findings, rules_executed)
}

fn run_detector(
    det: &dyn crate::core::Detector,
    ctx: &ScanContext,
    unit: &ParsedUnit,
    findings: &mut Vec<Finding>,
    timing: &mut TimingCollector,
) {
    if !timing.is_enabled() {
        det.run(ctx, unit, findings);
        return;
    }

    if multi_rule_self_times(det.rule_ids()) {
        // BP pack records per-rule spans via the thread-local active collector.
        // No outer pack span — avoids double-counting first-rule labels like "BP-1".
        crate::engine::with_active_collector(timing, || {
            det.run(ctx, unit, findings);
        });
    } else {
        // Single-rule or non-self-timing multi-rule packs (PERF/CWE): one span each.
        let name = pack_timing_name(det.rule_ids());
        timing.measure(name, || {
            det.run(ctx, unit, findings);
        });
    }
}

/// Packs that record their own per-rule spans via [`crate::engine::timing::measure_active`].
fn multi_rule_self_times(rule_ids: &[&'static str]) -> bool {
    rule_ids.len() > 1 && rule_ids.first().is_some_and(|id| id.starts_with("BP-"))
}

/// Stable timing label for a detector object (not the first rule alone for packs).
fn pack_timing_name(rule_ids: &[&'static str]) -> &'static str {
    match rule_ids.first().copied() {
        Some(id) if id.starts_with("PERF-") && rule_ids.len() > 1 => "GoPerfScan",
        Some(id) if id.starts_with("CWE-") && rule_ids.len() > 1 => "GoCweScan",
        Some(id) => id,
        None => "detector",
    }
}

fn reset_detector_after_panic(detector: &dyn crate::core::Detector) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| detector.reset_state())).is_err() {
        tracing::error!("detector reset_state panicked while recovering from a detector panic");
    }
}
