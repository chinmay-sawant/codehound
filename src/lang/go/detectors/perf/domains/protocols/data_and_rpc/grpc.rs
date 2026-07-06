#![allow(dead_code)]
//! PERF-96 and PERF-97: gRPC / protobuf performance detectors.

use super::super::super::super::common::is_in_loop;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-96: gRPC client allocates a new message struct inside the RecvMsg loop
/// instead of reusing one with msg.Reset().
pub(crate) fn detect_perf_96(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();
    if !facts.source_index.has_any(GRPC_MARKERS) || !facts.source_index.has("RecvMsg(") {
        return;
    }
    if facts.source_index.has("msg.Reset()") || facts.source_index.has("m.Reset()") {
        return;
    }
    for call in &facts.calls {
        if call.callee.as_ref() != "stream.RecvMsg" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let Some(loop_start) = call.enclosing_loop else {
            continue;
        };
        let has_alloc_in_loop = facts.assignments.iter().any(|a| {
            a.enclosing_loop == Some(loop_start)
                && (a.expr.contains("New") || (a.expr.contains('&') && a.expr.contains('{')))
        });
        if has_alloc_in_loop {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_96,
                file,
                line,
                col,
                "gRPC client allocates a new message inside the Recv loop; reuse a single message struct across iterations",
                out,
            );
            return;
        }
    }
}

/// PERF-97: proto.Marshal / protojson.Marshal invoked inside a loop without
/// buffer reuse.
pub(crate) fn detect_perf_97(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();
    if !facts.source_index.has("proto.Marshal") && !facts.source_index.has("protojson.Marshal") {
        return;
    }
    if facts.source_index.has("bytesPool")
        || facts.source_index.has("bufPool")
        || facts.source_index.has("MarshalBuffer")
    {
        return;
    }
    if facts.source_index.has("MarshalOptions{")
        && (facts.source_index.has("Pool") || facts.source_index.has("pool.Get"))
    {
        return;
    }
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if callee != "proto.Marshal" && callee != "protojson.Marshal" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_97,
            file,
            line,
            col,
            "proto.Marshal is called inside a loop; reuse a MarshalOptions/buffer pool to avoid repeated allocations",
            out,
        );
        return;
    }
}
