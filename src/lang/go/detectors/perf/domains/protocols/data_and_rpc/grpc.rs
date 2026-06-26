#![allow(dead_code)]
//! PERF-96 and PERF-97: gRPC / protobuf performance detectors.

use super::super::common::*;
use super::super::super::super::common::is_in_loop;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-96: gRPC client allocates a new message struct inside the RecvMsg loop
/// instead of reusing one with msg.Reset().
pub(crate) fn detect_perf_96(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, GRPC_MARKERS) || !source.contains("RecvMsg(") {
        return;
    }
    if source.contains("msg.Reset()") || source.contains("m.Reset()") {
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
    let source = unit.source.as_ref();
    if !source.contains("proto.Marshal") && !source.contains("protojson.Marshal") {
        return;
    }
    if source.contains("bytesPool")
        || source.contains("bufPool")
        || source.contains("MarshalBuffer")
    {
        return;
    }
    if source.contains("MarshalOptions{")
        && (source.contains("Pool") || source.contains("pool.Get"))
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
