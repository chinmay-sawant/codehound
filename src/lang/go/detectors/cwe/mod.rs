//! Bundled Go CWE heuristics.

pub mod common;
pub mod domains;
pub mod facts;
pub mod source_index;
pub mod taint;

mod metadata;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{
    DetectorEvidence, Finding, RuleMetadata, TaintHop, TaintSinkInfo, TaintSourceInfo,
};
use domains::*;
use facts::{FactBuildOpts, GoUnitFacts, build_go_unit_facts_with, build_taint_graph_for_facts};
use taint::{
    CallGraph, SharedText, SinkKind, TaintAnnotations, TaintGraph, TaintGraphIndex, TaintNode,
    TaintNodeId, build_import_map, build_index, detect_cwe_22_taint, detect_cwe_78_taint,
    detect_cwe_79_taint, detect_cwe_89_taint, detect_cwe_90_taint, detect_cwe_91_taint,
    forward_reaches_any_with_index, unsanitized_reaches_any_with_index,
};

use crate::rules::emit;

use self::metadata::{
    META_CWE_22, META_CWE_78, META_CWE_79, META_CWE_89, META_CWE_90, META_CWE_91,
};

type GoRuleFn = fn(&ParsedUnit, &GoUnitFacts, &mut Vec<Finding>);
type GoRuleEntry = (&'static str, GoRuleFn, &'static RuleMetadata);

include!(concat!(env!("OUT_DIR"), "/go_cwe_registry.rs"));

/// Accumulated per-file data for project-level taint analysis.
///
/// Built **outside** the project lock, then pushed under a short critical
/// section. `line_starts` is `Arc` so finalize can share without cloning.
struct ProjectUnit {
    path: String,
    source: Arc<str>,
    line_starts: Arc<[usize]>,
    call_graph: CallGraph,
    annotations: TaintAnnotations,
    taint_graph: TaintGraph,
    import_map: HashMap<String, String>,
}

/// Cross-file detector concurrency contract:
///
/// - `run(unit)` may execute in parallel across files (Rayon).
/// - Project units are assembled off-lock, then pushed under a `Mutex`.
///   Poison is recovered via `into_inner()` so an isolated detector panic
///   does not hard-crash the CLI.
/// - When taint is **disabled**, no project state is retained (no Mutex
///   traffic, no source clone into project state).
/// - `finalize` runs single-threaded after workers finish.
///
/// Shared state accumulated across all files in a scan.
struct ProjectTaintState {
    units: Vec<ProjectUnit>,
}

pub struct GoCweScan {
    state: Mutex<ProjectTaintState>,
}

impl GoCweScan {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(ProjectTaintState { units: Vec::new() }),
        }
    }
}

impl Default for GoCweScan {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for GoCweScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        self::metadata::GO_CWE_RULE_IDS
    }

    fn metadata_for(&self, rule_id: &str) -> Option<&'static RuleMetadata> {
        GO_RULES
            .iter()
            .find(|(id, _, _)| *id == rule_id)
            .map(|(_, _, meta)| *meta)
    }

    fn accumulate_state(&self, ctx: &ScanContext, unit: &ParsedUnit) {
        // Project state is only consumed by taint finalize.
        if !ctx.taint_enabled || !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        let mut facts = build_go_unit_facts_with(unit, FactBuildOpts::TAINT);
        build_taint_graph_for_facts(&mut facts);
        let project_unit = make_project_unit(unit, &mut facts);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.units.push(project_unit);
    }

    fn requires_cache_state(&self, ctx: &ScanContext) -> bool {
        ctx.taint_enabled && self.rule_ids().iter().any(|id| ctx.allows(id))
    }

    fn reset_state(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.units.clear();
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        let opts = FactBuildOpts::for_scan(ctx.taint_enabled);
        let mut facts = build_go_unit_facts_with(unit, opts);
        if ctx.taint_enabled {
            build_taint_graph_for_facts(&mut facts);
        }

        for (rule_id, detector, _) in GO_RULES {
            if ctx.allows(rule_id) {
                detector(unit, &facts, out);
            }
        }

        // Publish project state only after every per-file rule succeeds. If a
        // rule panics, the worker result is discarded and this file cannot
        // leak a partially analyzed unit into project finalization.
        if ctx.taint_enabled {
            let project_unit = make_project_unit(unit, &mut facts);
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.units.push(project_unit);
        }
    }

    fn finalize(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        if !ctx.taint_enabled {
            return;
        }

        let mut units = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut state.units)
        };
        if units.is_empty() {
            return;
        }

        // Stable order so duplicate function names resolve the same way
        // regardless of parallel scan vs cache-hit accumulation order.
        units.sort_by(|a, b| a.path.cmp(&b.path));

        // Pre-build per-file taint graphs and summaries.
        let mut per_file: Vec<(
            &str,
            TaintGraph,
            TaintGraphIndex,
            HashMap<String, taint::TaintSummary>,
        )> = Vec::with_capacity(units.len());
        let mut func_to_file: HashMap<String, usize> = HashMap::new();
        let max_depth = ctx.taint_max_depth.clamp(1, 4);
        let graphs: Vec<TaintGraph> = units
            .iter_mut()
            .map(|unit| std::mem::take(&mut unit.taint_graph))
            .collect();
        for (idx, (unit, graph)) in units.iter().zip(graphs).enumerate() {
            // The graph was built once alongside the per-file facts and is
            // moved here for project-level queries. Rebuilding it would repeat
            // the same annotation walk before every summary/finalization pass.
            let graph_index = build_index(&graph);
            let mut summaries = taint::compute_all_summaries_with_graph_and_index(
                &graph,
                &graph_index,
                &unit.annotations,
                &unit.source,
            );
            // Bounded multi-hop: refine return_sources through same-file call graph.
            if max_depth > 1 {
                taint::refine_summaries_multihop_with_context(
                    &unit.call_graph,
                    &unit.annotations,
                    &mut summaries,
                    max_depth,
                );
            }
            per_file.push((unit.path.as_str(), graph, graph_index, summaries));
            for func_name in unit.call_graph.declarations.keys() {
                // Prefer same-package path + name; avoid cross-file name collisions
                // by keying with file index when inserting first-wins.
                func_to_file.entry(func_name.to_string()).or_insert(idx);
            }
        }

        // Index project-wide lookups once before walking call sites. These
        // maps preserve the existing first-file-wins resolution semantics
        // without repeatedly scanning every file or graph.
        let variable_indexes: Vec<VariableIndex> = per_file
            .iter()
            .map(|(_, graph, _, _)| build_variable_index(graph))
            .collect();
        let mut summary_index: HashMap<String, usize> = HashMap::new();
        for (file_idx, (_, _, _, summaries)) in per_file.iter().enumerate() {
            for name in summaries.keys() {
                summary_index.entry(name.clone()).or_insert(file_idx);
            }
        }
        let imported_prefixes: HashSet<String> = units
            .iter()
            .flat_map(|unit| unit.import_map.keys().cloned())
            .collect();

        // Phase 2 + 3: Walk each file's call sites in place. Using the merged
        // project graph + func_to_file lookup was nondeterministic when the
        // same function name appears in multiple files (parallel scan order
        // decided which file "won").
        for (caller_idx, unit) in units.iter().enumerate() {
            let caller_path = unit.path.as_str();
            let caller_graph = &per_file[caller_idx].1;
            let caller_index = &per_file[caller_idx].2;
            let caller_variables = &variable_indexes[caller_idx];
            let caller_line_starts = &unit.line_starts;

            for site in &unit.call_graph.sites {
                let raw_callee = site.callee.as_ref();
                // ponytail: skip external package calls when we can resolve
                // the import prefix — prevents matching user-defined functions
                // that share a name with a stdlib function.
                if site.is_method_call {
                    if let Some(dot) = raw_callee.rfind('.') {
                        let prefix = &raw_callee[..dot];
                        let is_imported = imported_prefixes.contains(prefix);
                        let is_internal = func_to_file.contains_key(&raw_callee[dot + 1..]);
                        if is_imported && !is_internal {
                            continue;
                        }
                    }
                }
                let callee_name = resolve_callee_name(raw_callee, site.is_method_call);
                let callee_summary = find_callee_summary(&per_file, &summary_index, raw_callee)
                    .or_else(|| find_callee_summary(&per_file, &summary_index, &callee_name));
                let Some(callee_summary) = callee_summary else {
                    continue;
                };

                // 1) Param sources: argument[i] is tainted → callee passes to sink.
                for (i, is_source) in callee_summary.param_sources.iter().enumerate() {
                    let Some(true) = is_source else { continue };
                    let Some(arg_text) = site.arguments.get(i) else {
                        continue;
                    };
                    if !is_identifier_tainted(
                        caller_graph,
                        caller_index,
                        caller_variables,
                        arg_text,
                    ) {
                        continue;
                    }
                    emit_inter_procedural_finding(
                        caller_path,
                        caller_line_starts,
                        caller_graph,
                        &callee_name,
                        site,
                        &callee_summary.sink_kinds,
                        arg_text.as_ref(),
                        ctx,
                        out,
                    );
                }

                // 2) Return sources: callee returns tainted data → check if
                //    the result variable reaches a sink in the caller.
                for (ret_idx, is_ret_source) in callee_summary.return_sources.iter().enumerate() {
                    if !is_ret_source {
                        continue;
                    }
                    let result_var = site
                        .assignment_lhs
                        .as_deref()
                        .and_then(|lhs| taint::result_variable_at_return_index(lhs, ret_idx));
                    let Some(result_var) = result_var else {
                        continue;
                    };
                    let reached_sinks = sink_kinds_reached_by_var(
                        caller_graph,
                        caller_index,
                        caller_variables,
                        &result_var,
                    );
                    if reached_sinks.is_empty() {
                        continue;
                    }
                    emit_inter_procedural_finding(
                        caller_path,
                        caller_line_starts,
                        caller_graph,
                        &callee_name,
                        site,
                        &reached_sinks,
                        &result_var,
                        ctx,
                        out,
                    );
                }

                // 3) Output pointer params: callee writes tainted data through
                //    a `*T` parameter (`*p = source()`).  If the caller passed
                //    `&var`, check if `var` reaches a sink in the caller.
                for &out_idx in &callee_summary.output_pointer_params {
                    let Some(arg_text) = site.arguments.get(out_idx) else {
                        continue;
                    };
                    let var_name = arg_text.strip_prefix('&').unwrap_or(arg_text).trim();
                    let reached_sinks = sink_kinds_reached_by_var(
                        caller_graph,
                        caller_index,
                        caller_variables,
                        var_name,
                    );
                    if reached_sinks.is_empty() {
                        continue;
                    }
                    emit_inter_procedural_finding(
                        caller_path,
                        caller_line_starts,
                        caller_graph,
                        &callee_name,
                        site,
                        &reached_sinks,
                        var_name,
                        ctx,
                        out,
                    );
                }
            }
        }
    }
}

// --- Inter-procedural analysis helpers ---

type VariableIndex = HashMap<SharedText, Vec<TaintNodeId>>;

fn build_variable_index(graph: &TaintGraph) -> VariableIndex {
    let mut index = HashMap::new();
    for (id, node) in graph.nodes.iter().enumerate() {
        if let TaintNode::Variable { name, .. } = node {
            index
                .entry(Arc::clone(name))
                .or_insert_with(Vec::new)
                .push(id);
        }
    }
    index
}

fn make_project_unit(unit: &ParsedUnit, facts: &mut GoUnitFacts) -> ProjectUnit {
    ProjectUnit {
        path: unit.display_path.clone(),
        source: Arc::clone(&unit.source),
        line_starts: Arc::from(unit.line_starts.as_slice()),
        call_graph: facts.call_graph.clone().unwrap_or_default(),
        annotations: facts.taint.clone(),
        taint_graph: facts.taint_graph.take().unwrap_or_default(),
        import_map: build_import_map(unit),
    }
}

/// Find a callee's TaintSummary across all files.
fn find_callee_summary<'a>(
    per_file: &'a [(
        &str,
        TaintGraph,
        TaintGraphIndex,
        HashMap<String, taint::TaintSummary>,
    )],
    summary_index: &HashMap<String, usize>,
    callee_name: &str,
) -> Option<&'a taint::TaintSummary> {
    summary_index
        .get(callee_name)
        .and_then(|file_idx| per_file.get(*file_idx))
        .and_then(|(_, _, _, summaries)| summaries.get(callee_name))
}

/// Check if any identifier text in a TaintGraph has an **unsanitized** taint
/// path from any source.
fn is_identifier_tainted(
    graph: &TaintGraph,
    graph_index: &TaintGraphIndex,
    variable_index: &VariableIndex,
    name: &str,
) -> bool {
    // Check 1: Variable nodes with this name have taint paths.
    let var_ids = variable_index.get(name).map(Vec::as_slice).unwrap_or(&[]);
    if !var_ids.is_empty() {
        for source_ids in graph.by_source.values() {
            for source_id in source_ids {
                if unsanitized_reaches_any_with_index(
                    graph,
                    graph_index.adjacency(),
                    *source_id,
                    var_ids,
                ) {
                    return true;
                }
            }
        }
    }

    // ponytail: Check 2 — the name might be a direct source call expression
    // (e.g. `f(r.URL.Query().Get("input"))`).  Extract the function name from
    // the call and check against known sources.
    let call_func = name.split('(').next().unwrap_or("").trim();
    if !call_func.is_empty() {
        for source_ids in graph.by_source.values() {
            for source_id in source_ids {
                if let Some(TaintNode::Source { function, .. }) = graph.nodes.get(*source_id) {
                    if function.as_ref() == call_func {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Map a SinkKind to the corresponding RuleMetadata for finding emission.
fn sink_kind_meta(kind: SinkKind) -> Option<&'static RuleMetadata> {
    match kind {
        SinkKind::FileOpen => Some(&META_CWE_22),
        SinkKind::CommandExec => Some(&META_CWE_78),
        SinkKind::Template | SinkKind::HTTPWrite => Some(&META_CWE_79),
        SinkKind::SQLQuery => Some(&META_CWE_89),
        SinkKind::LDAPQuery => Some(&META_CWE_90),
        SinkKind::XMLQuery | SinkKind::Deserialization => Some(&META_CWE_91),
    }
}

/// Resolve a callee name for lookup.  For method calls like `h.openFile`,
/// extract just the method name `openFile`.
fn resolve_callee_name(callee: &str, is_method_call: bool) -> String {
    if is_method_call {
        if let Some(dot) = callee.rfind('.') {
            return callee[dot + 1..].to_string();
        }
    }
    callee.to_string()
}

/// Which sink kinds does a variable reach in the TaintGraph (forward BFS)?
fn sink_kinds_reached_by_var(
    graph: &TaintGraph,
    graph_index: &TaintGraphIndex,
    variable_index: &VariableIndex,
    var_name: &str,
) -> Vec<SinkKind> {
    let var_ids = variable_index
        .get(var_name)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if var_ids.is_empty() {
        return Vec::new();
    }
    let mut reached = Vec::new();
    for &sk in [
        SinkKind::FileOpen,
        SinkKind::CommandExec,
        SinkKind::SQLQuery,
        SinkKind::Template,
        SinkKind::HTTPWrite,
        SinkKind::LDAPQuery,
        SinkKind::XMLQuery,
        SinkKind::Deserialization,
    ]
    .iter()
    {
        if let Some(sink_ids) = graph.by_sink.get(&sk) {
            if forward_reaches_any_with_index(graph, graph_index.adjacency(), var_ids, sink_ids) {
                reached.push(sk);
            }
        }
    }
    reached
}

/// Emit findings for a cross-function taint flow.
#[allow(clippy::too_many_arguments)]
fn emit_inter_procedural_finding(
    file: &str,
    line_starts: &[usize],
    _graph: &TaintGraph,
    _callee_name: &str,
    site: &taint::CallSite,
    sink_kinds: &[SinkKind],
    arg_text: &str,
    ctx: &ScanContext,
    out: &mut Vec<Finding>,
) {
    let (line, col) = crate::ast::line_col_with_starts(line_starts, site.byte_range.start);
    for &sk in sink_kinds {
        let meta = match sink_kind_meta(sk) {
            Some(m) => m,
            None => continue,
        };
        if !ctx.allows(meta.id) {
            continue;
        }
        let msg = format!(
            "tainted data reaches {} via call crossing function boundary",
            meta.title
        );
        let sink_kind_str = format!("{sk:?}");
        let hop_details = if ctx.taint_show_paths {
            vec![TaintHop {
                function: site.callee.to_string(),
                kind: sink_kind_str,
                variable: arg_text.to_string(),
                file: file.to_string(),
                line,
            }]
        } else {
            Vec::new()
        };
        emit::push_finding_with_evidence(
            meta,
            file,
            line,
            col,
            &msg,
            DetectorEvidence::TaintFlow {
                source: TaintSourceInfo {
                    kind: "UserInput".to_string(),
                    function: "unknown".to_string(),
                    variable: arg_text.to_string(),
                },
                sink: TaintSinkInfo {
                    kind: format!("{sk:?}"),
                    function: site.callee.to_string(),
                    hop_details,
                },
                hops: 1,
                sanitized: false,
            },
            out,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_index_groups_scoped_nodes_by_name() {
        let mut graph = TaintGraph::default();
        graph.add_node(TaintNode::Variable {
            name: Arc::from("value"),
            type_hint: None,
            scope: 1,
            decl_byte: 10,
        });
        graph.add_node(TaintNode::Variable {
            name: Arc::from("value"),
            type_hint: None,
            scope: 2,
            decl_byte: 20,
        });

        let index = build_variable_index(&graph);

        assert_eq!(index.get("value").map(Vec::len), Some(2));
    }
}
