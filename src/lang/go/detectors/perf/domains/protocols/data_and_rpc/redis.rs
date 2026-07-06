#![allow(dead_code)]
//! PERF-98: go-redis client performance detector.

use super::super::super::super::common::is_in_loop;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-98: go-redis sequential client calls in a loop without using
/// Pipeline / Pipelined / TxPipeline.
pub(crate) fn detect_perf_98(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();
    if !facts.source_index.has_any(REDIS_MARKERS) {
        return;
    }
    if facts.source_index.has(".Pipeline()")
        || facts.source_index.has(".Pipelined(")
        || facts.source_index.has(".TxPipeline()")
        || facts.source_index.has(".TxPipelined(")
    {
        return;
    }
    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !REDIS_LOOP_TRIGGERS
            .iter()
            .any(|t| call.callee.as_ref() == *t)
        {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_98,
            file,
            line,
            col,
            "go-redis client is called inside a loop without a pipeline; batch the calls with rdb.Pipeline() to amortise round-trips",
            out,
        );
        return;
    }
}
