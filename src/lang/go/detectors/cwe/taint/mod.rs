//! Taint-analysis data model and fact extraction for Go CWE detectors.
//!
//! Graphs are built per source unit, then bounded same-package
//! inter-procedural summaries are refined during project finalization.

mod extract;
mod graph_query;
mod kinds;
mod model;
pub(crate) mod rules;

pub(crate) use extract::result_variable_at_return_index;
pub use extract::{build_import_map, extract_call_graph, extract_taint_facts, merge_call_graphs};
pub use kinds::{ScopeId, SharedText, TaintNodeId};
pub use model::{
    AssignmentDetail, CallGraph, CallSite, ChannelRecvSite, ChannelSendSite, ChannelTransfer,
    EdgeKind, FunctionDecl, PackageIdentity, ProjectCallGraph, SanitizerKind, ScopeInfo, ScopeKind,
    SinkKind, SourceKind, TaintAnnotations, TaintEdge, TaintGraph, TaintNode,
    TaintSanitizerAnnotation, TaintSinkAnnotation, TaintSourceAnnotation, TaintSummary,
    TaintSymbolKey, UnsupportedFlow, UnsupportedFlowKind, normalize_receiver_type,
    package_clause_name,
};

pub use rules::{
    detect_cwe_22_taint, detect_cwe_78_taint, detect_cwe_79_taint, detect_cwe_89_taint,
    detect_cwe_90_taint, detect_cwe_91_taint,
};

pub(crate) use graph_query::{
    TaintGraphIndex, build_index, compute_all_summaries_with_graph_and_index,
    forward_reaches_any_with_index, unsanitized_reaches_any_with_index,
};
pub use graph_query::{
    TaintPath, build_taint_graph, compute_all_summaries, compute_all_summaries_with_graph,
    find_taint_paths, find_taint_paths_from_nodes, forward_reaches_any, refine_summaries_multihop,
    refine_summaries_multihop_with_context, unsanitized_reaches_any,
};
