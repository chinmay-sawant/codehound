//! Machine-readable evidence attached to findings.
use serde::{Deserialize, Serialize};

use crate::rules::LineCol;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
/// Structured evidence emitted by a detector.
pub enum DetectorEvidence {
    /// Taint flow from a source through optional propagation hops to a sink.
    TaintFlow {
        /// Source metadata.
        source: TaintSourceInfo,
        /// Sink metadata.
        sink: TaintSinkInfo,
        /// Number of propagation hops.
        hops: usize,
        /// Whether every reported path was sanitized.
        sanitized: bool,
    },
    /// Control-flow-related finding context.
    ControlFlowIssue {
        /// Kind of control-flow issue.
        control_flow_kind: ControlFlowKind,
        /// Source location of the issue.
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
/// Source-side metadata for a taint flow.
pub struct TaintSourceInfo {
    /// Source category.
    pub kind: String,
    /// Source function name.
    pub function: String,
    /// Variable carrying the source value.
    pub variable: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Sink-side metadata for a taint flow.
pub struct TaintSinkInfo {
    /// Sink category.
    pub kind: String,
    /// Sink function name.
    pub function: String,
    /// ponytail: per-hop details, only populated when --taint-show-paths
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hop_details: Vec<TaintHop>,
}

impl TaintSinkInfo {
    /// Create sink metadata without hop details.
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
    /// Function containing this hop.
    pub function: String,
    /// Propagation kind.
    pub kind: String,
    /// Variable carrying the value.
    pub variable: String,
    /// File containing the hop.
    pub file: String,
    /// One-indexed source line.
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// Categories of control-flow evidence.
pub enum ControlFlowKind {
    /// Allocation occurs in a loop body.
    LoopBodyAllocation,
}
