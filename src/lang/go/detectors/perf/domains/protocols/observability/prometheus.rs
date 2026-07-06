#![allow(dead_code)]
//! PERF-99: Prometheus high-cardinality label detector.

use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-99: Prometheus metric registers high-cardinality labels (user ID,
/// UUID, path) that cause time-series storage explosion.
pub(crate) fn detect_perf_99(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();
    if !facts.source_index.has_any(PROM_MARKERS) {
        return;
    }
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !matches!(
            callee,
            "prometheus.NewCounterVec"
                | "prometheus.NewGaugeVec"
                | "prometheus.NewHistogramVec"
                | "prometheus.NewSummaryVec"
        ) {
            continue;
        }
        for arg in &call.arguments {
            let t = arg.as_ref();
            if HIGH_CARDINALITY_LABELS.iter().any(|n| t.contains(n)) {
                let (line, col) = unit.line_col(call.start_byte);
                emit::push_finding(
                    &META_PERF_99,
                    file,
                    line,
                    col,
                    "Prometheus metric registers a high-cardinality label (user ID / UUID / path); time series storage will explode — bound the label space",
                    out,
                );
                return;
            }
        }
    }
}
