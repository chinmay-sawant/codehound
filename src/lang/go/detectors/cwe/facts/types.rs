//! Public fact types.

use std::sync::Arc;

use super::super::source_index::SourceIndex;
use super::super::taint::{TaintAnnotations, TaintGraph};

pub type SharedText = Arc<str>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    UserControlled,
    TrustedConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBinding {
    pub name: SharedText,
    pub kind: InputKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFact {
    pub callee: SharedText,
    pub arguments: Box<[SharedText]>,
    pub start_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentFact {
    pub name: SharedText,
    pub expr: SharedText,
    pub start_byte: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GoUnitFacts {
    pub input_bindings: Vec<InputBinding>,
    pub call_facts: Vec<CallFact>,
    pub assignments: Vec<AssignmentFact>,
    /// Single-pass substring flags for hot detector guards.
    pub source_index: SourceIndex,
    /// Taint annotations extracted in a single additional tree-sitter pass.
    pub taint: TaintAnnotations,
    /// Built only when `[taint] enabled = true`.
    pub taint_graph: Option<TaintGraph>,
}
