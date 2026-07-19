//! Run enabled detectors on an already-parsed unit.

use crate::core::{ParsedUnit, ScanContext};
use crate::engine::registry::Registry;
use crate::engine::timing::TimingCollector;
use crate::rules::{Finding, TimingGranularity};

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

    match det.timing_granularity() {
        // Pack records per-rule spans via the thread-local active collector.
        // No outer pack span — avoids double-counting first-rule labels.
        TimingGranularity::PerRuleSelfTimed => {
            crate::engine::with_active_collector(timing, || {
                det.run(ctx, unit, findings);
            });
        }
        TimingGranularity::DetectorSpan | TimingGranularity::SingleRule => {
            timing.measure(det.timing_label(), || {
                det.run(ctx, unit, findings);
            });
        }
    }
}

fn reset_detector_after_panic(detector: &dyn crate::core::Detector) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| detector.reset_state())).is_err() {
        tracing::error!("detector reset_state panicked while recovering from a detector panic");
    }
}
