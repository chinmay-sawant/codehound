//! Machine-readable evidence attached to findings.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use serde::{Deserialize, Serialize};

use crate::rules::LineCol;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum DetectorEvidence {
    PatternMatch {
        pattern: String,
        match_location: LineCol,
    },
    DangerousCall {
        function: String,
        argument_index: Option<usize>,
    },
    TaintFlow {
        source: TaintSourceInfo,
        sink: TaintSinkInfo,
        hops: usize,
        sanitized: bool,
    },
    MissingConfig {
        struct_name: String,
        field: String,
    },
    ControlFlowIssue {
        control_flow_kind: ControlFlowKind,
        location: LineCol,
    },
    Other {
        data: serde_json::Value,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintSourceInfo {
    pub kind: String,
    pub function: String,
    pub variable: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintSinkInfo {
    pub kind: String,
    pub function: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlFlowKind {
    LoopBodyAllocation,
    DeferInLoop,
    MissingErrorCheck,
}
