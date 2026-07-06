//! Taint-analysis data model and fact extraction for Go CWE detectors.
//!
//! This module is intentionally scoped to the intra-procedural MVP described
//! in `plans/taint-tracking-architecture.md`. Cross-function tracking is
//! reserved for a later phase.

mod extract;
mod graph_query;
mod kinds;
mod model;
pub mod rules;

pub(crate) use extract::result_variable_at_return_index;
pub use extract::{build_import_map, extract_call_graph, extract_taint_facts, merge_call_graphs};
pub use kinds::{ScopeId, SharedText, TaintNodeId};
pub use model::{
    AssignmentDetail, CallGraph, CallSite, EdgeKind, FunctionDecl, ProjectCallGraph, SanitizerKind,
    ScopeInfo, ScopeKind, SinkKind, SourceKind, TaintAnnotations, TaintEdge, TaintGraph, TaintNode,
    TaintSanitizerAnnotation, TaintSinkAnnotation, TaintSourceAnnotation, TaintSummary,
};

pub use rules::{
    detect_cwe_22_taint, detect_cwe_78_taint, detect_cwe_79_taint, detect_cwe_89_taint,
    detect_cwe_90_taint, detect_cwe_91_taint,
};

pub use graph_query::{
    TaintPath, build_taint_graph, compute_all_summaries, find_taint_paths,
    find_taint_paths_from_nodes, forward_reaches_any, unsanitized_reaches_any,
};
