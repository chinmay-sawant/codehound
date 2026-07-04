//! Machine-readable evidence attached to findings.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use serde::{Deserialize, Serialize};

use crate::rules::LineCol;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum DetectorEvidence {
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
    ControlFlowIssue {
        control_flow_kind: ControlFlowKind,
        location: LineCol,
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
    /// ponytail: per-hop details, only populated when --taint-show-paths
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hop_details: Vec<TaintHop>,
}

impl TaintSinkInfo {
    pub fn new(kind: impl Into<String>, function: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            function: function.into(),
            hop_details: Vec::new(),
        }
    }
}

/// One step in a taint propagation path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintHop {
    pub function: String,
    pub kind: String,
    pub variable: String,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlFlowKind {
    LoopBodyAllocation,
}
