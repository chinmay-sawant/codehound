use std::collections::HashMap;
use std::sync::Arc;

use super::super::source_index::PerfSourceIndex;

pub(super) type SharedText = Arc<str>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFact {
    pub callee: SharedText,
    pub arguments: Box<[SharedText]>,
    pub start_byte: usize,
    pub enclosing_loop: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentFact {
    pub name: SharedText,
    pub expr: SharedText,
    /// Full text of the assignment node, including any compound-assignment
    /// operator (e.g. `s += strconv.Itoa(v)`). Detectors that care about the
    /// operator consult this instead of reconstructing it from `name` + `expr`.
    pub text: SharedText,
    pub start_byte: usize,
    pub enclosing_loop: Option<usize>,
}

/// Coarse classification of a variable's type based on its declaration site.
///
/// This is intentionally narrow: it only needs to tell numeric accumulators
/// (`totalDur += d`) apart from string concatenations (`s += "..."`). Unknown
/// means "could not determine" — detectors should treat Unknown as
/// permissive, not as "definitely numeric".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarKind {
    Numeric,
    String,
    Bytes,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GoPerfFacts {
    pub calls: Vec<CallFact>,
    pub assignments: Vec<AssignmentFact>,
    /// Single-pass substring flags for hot detector guards.
    pub source_index: PerfSourceIndex,
    /// Variable-name → coarse type, derived from `var` specs and short-var
    /// declarations in the current file. Used to suppress heuristics that
    /// would otherwise misfire on numeric accumulators (e.g. PERF-2 firing
    /// on `totalDur := 0.0` + `totalDur += d`).
    pub var_kinds: HashMap<SharedText, VarKind>,
    pub defer_starts: Vec<(usize, usize)>,
    pub go_starts: Vec<(usize, usize)>,
    pub for_ranges: Vec<(usize, usize)>,
    pub function_literal_ranges: Vec<(usize, usize)>,
    pub type_assertions: Vec<(usize, usize)>,
}

#[derive(Default)]
pub(crate) struct SharedTextInterner<'a> {
    pub(crate) values: HashMap<&'a str, SharedText>,
}

impl<'a> SharedTextInterner<'a> {
    pub(crate) fn intern(&mut self, text: &'a str) -> SharedText {
        if let Some(existing) = self.values.get(text) {
            return Arc::clone(existing);
        }

        let shared: SharedText = Arc::from(text);
        self.values.insert(text, Arc::clone(&shared));
        shared
    }
}
