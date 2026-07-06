//! Machine-readable evidence attached to findings.
#![allow(missing_docs)] // ratchet: document in a follow-up pass

use serde::{Deserialize, Serialize};

use crate::rules::LineCol;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum DetectorEvidence {
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

impl DetectorEvidence {
    /// Returns `Some(true)` when taint hop details are present (from `--taint-show-paths`).
    pub fn taint_show_paths_flag(&self) -> Option<bool> {
        match self {
            Self::TaintFlow { sink, .. } if !sink.hop_details.is_empty() => Some(true),
            _ => None,
        }
    }
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
