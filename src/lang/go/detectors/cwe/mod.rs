//! Bundled Go CWE heuristics.

pub mod common;
pub mod domains;
pub mod facts;
pub mod source_index;
pub mod taint;

mod metadata;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{
    DetectorEvidence, Finding, Rule, RuleMetadata, TaintHop, TaintSinkInfo, TaintSourceInfo,
};
use domains::*;
use facts::{GoUnitFacts, build_go_unit_facts, build_taint_graph_for_facts};
use taint::{
    CallGraph, SinkKind, TaintAnnotations, TaintGraph, TaintNode, TaintNodeId, build_import_map,
};

use crate::rules::emit;

use self::metadata::{
    META_CWE_22, META_CWE_78, META_CWE_79, META_CWE_89, META_CWE_90, META_CWE_91,
};

type GoRuleFn = fn(&ParsedUnit, &GoUnitFacts, &mut Vec<Finding>);
type GoRuleEntry = (&'static str, GoRuleFn, &'static RuleMetadata);

include!(concat!(env!("OUT_DIR"), "/go_cwe_registry.rs"));

/// Accumulated per-file data for project-level taint analysis.
struct ProjectUnit {
    path: String,
    source: Arc<str>,
    call_graph: CallGraph,
    annotations: TaintAnnotations,
    import_map: HashMap<String, String>,
}

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

impl Rule for GoCweScan {
    fn metadata(&self) -> RuleMetadata {
        GO_RULES
            .first()
            .map(|(_, _, meta)| (*meta).clone())
            .expect("GO_RULES must not be empty")
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
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        let mut facts = build_go_unit_facts(unit);
        if ctx.taint_enabled {
            build_taint_graph_for_facts(&mut facts);
        }
        let mut state = self.state.lock().expect("lock CweDetector state");
        state.units.push(ProjectUnit {
            path: unit.display_path.clone(),
            source: Arc::clone(&unit.source),
            call_graph: facts.call_graph.clone().unwrap_or_default(),
            annotations: facts.taint.clone(),
            import_map: build_import_map(unit),
        });
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        let mut facts = build_go_unit_facts(unit);
        if ctx.taint_enabled {
            build_taint_graph_for_facts(&mut facts);
        }

        // Accumulate state for project-level analysis.
        {
            let mut state = self.state.lock().expect("lock CweDetector state");
            state.units.push(ProjectUnit {
                path: unit.display_path.clone(),
                source: Arc::clone(&unit.source),
                call_graph: facts.call_graph.clone().unwrap_or_default(),
                annotations: facts.taint.clone(),
                import_map: build_import_map(unit),
            });
        }

        for (rule_id, detector, _) in GO_RULES {
            if ctx.allows(rule_id) {
                detector(unit, &facts, out);
            }
        }
    }

    fn finalize(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        if !ctx.taint_enabled {
            return;
        }

        let mut state = self.state.lock().expect("lock CweDetector state");
        if state.units.is_empty() {
            return;
        }

        // Phase 1.3: Merge per-file call graphs.
        let project_cg =
            taint::merge_call_graphs(state.units.iter().map(|u| (u.path.as_str(), &u.call_graph)));

        // Pre-build per-file taint graphs and summaries.
        let mut per_file: Vec<(&str, TaintGraph, HashMap<String, taint::TaintSummary>)> =
            Vec::with_capacity(state.units.len());
        let mut func_to_file: HashMap<String, usize> = HashMap::new();
        for (idx, unit) in state.units.iter().enumerate() {
            let graph = taint::build_taint_graph(&unit.annotations);
            let summaries = taint::compute_all_summaries(&unit.annotations, &unit.source);
            per_file.push((unit.path.as_str(), graph, summaries));
            for func_name in unit.call_graph.declarations.keys() {
                func_to_file.insert(func_name.to_string(), idx);
            }
        }

        // Phase 2 + 3: For each call site, check if callee has a param_source.
        for (caller_name, sites) in &project_cg.calls {
            let caller_idx = match func_to_file.get(caller_name) {
                Some(&idx) => idx,
                None => continue,
            };
            let caller_path = state.units[caller_idx].path.as_str();
            let caller_graph = &per_file[caller_idx].1;
            let caller_source = &state.units[caller_idx].source;

            for site in sites {
                let raw_callee = site.callee.as_ref();
                // ponytail: skip external package calls when we can resolve
                // the import prefix — prevents matching user-defined functions
                // that share a name with a stdlib function.
                if site.is_method_call {
                    if let Some(dot) = raw_callee.rfind('.') {
                        let prefix = &raw_callee[..dot];
                        let is_imported = state
                            .units
                            .iter()
                            .any(|u| u.import_map.contains_key(prefix));
                        let is_internal = func_to_file.contains_key(&raw_callee[dot + 1..]);
                        if is_imported && !is_internal {
                            continue;
                        }
                    }
                }
                let callee_name = resolve_callee_name(raw_callee, site.is_method_call);
                let callee_summary = find_callee_summary(&per_file, raw_callee)
                    .or_else(|| find_callee_summary(&per_file, &callee_name));
                let Some(callee_summary) = callee_summary else {
                    continue;
                };

                // 1) Param sources: argument[i] is tainted → callee passes to sink.
                for (i, is_source) in callee_summary.param_sources.iter().enumerate() {
                    let Some(true) = is_source else { continue };
                    let Some(arg_text) = site.arguments.get(i) else {
                        continue;
                    };
                    if !is_identifier_tainted(caller_graph, arg_text) {
                        continue;
                    }
                    emit_inter_procedural_finding(
                        caller_path,
                        caller_source,
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
                    let result_var =
                        result_variable_of_call(caller_source, site.byte_range.start, ret_idx);
                    let Some(result_var) = result_var else {
                        continue;
                    };
                    let reached_sinks = sink_kinds_reached_by_var(caller_graph, &result_var);
                    if reached_sinks.is_empty() {
                        continue;
                    }
                    emit_inter_procedural_finding(
                        caller_path,
                        caller_source,
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
                    let reached_sinks = sink_kinds_reached_by_var(caller_graph, var_name);
                    if reached_sinks.is_empty() {
                        continue;
                    }
                    emit_inter_procedural_finding(
                        caller_path,
                        caller_source,
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

        state.units.clear();
    }
}

// --- Inter-procedural analysis helpers ---

/// Find a callee's TaintSummary across all files.
fn find_callee_summary<'a>(
    per_file: &'a [(&str, TaintGraph, HashMap<String, taint::TaintSummary>)],
    callee_name: &str,
) -> Option<&'a taint::TaintSummary> {
    for (_, _, summaries) in per_file {
        if let Some(s) = summaries.get(callee_name) {
            return Some(s);
        }
    }
    None
}

/// Check if any identifier text in a TaintGraph has an **unsanitized** taint
/// path from any source.
fn is_identifier_tainted(graph: &TaintGraph, name: &str) -> bool {
    // Check 1: Variable nodes with this name have taint paths.
    let var_ids: Vec<TaintNodeId> = graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| matches!(n, TaintNode::Variable { name: n2, .. } if n2.as_ref() == name))
        .map(|(id, _)| id)
        .collect();
    if !var_ids.is_empty() {
        for source_ids in graph.by_source.values() {
            for source_id in source_ids {
                if bfs_sanitized_reaches(graph, *source_id, &var_ids, &[]) {
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

/// BFS from `start` to any of `targets`, tracking sanitized state.
/// Returns true only if an UNSANITIZED path exists.
fn bfs_sanitized_reaches(
    graph: &TaintGraph,
    start: TaintNodeId,
    targets: &[TaintNodeId],
    _allowed_sanitizers: &[taint::SanitizerKind],
) -> bool {
    use std::collections::VecDeque;

    let mut adj: HashMap<TaintNodeId, Vec<TaintNodeId>> = HashMap::new();
    for edge in &graph.edges {
        adj.entry(edge.from).or_default().push(edge.to);
    }

    let mut queue: VecDeque<(TaintNodeId, bool)> = VecDeque::new();
    let mut visited = vec![false; graph.nodes.len()];
    queue.push_back((start, false));
    visited[start] = true;

    while let Some((current, was_sanitized)) = queue.pop_front() {
        let sanitized =
            was_sanitized || matches!(graph.nodes.get(current), Some(TaintNode::Sanitizer { .. }));

        if targets.contains(&current) && !sanitized {
            return true;
        }

        for &next in adj.get(&current).into_iter().flatten() {
            if !visited[next] {
                visited[next] = true;
                queue.push_back((next, sanitized));
            }
        }
    }
    false
}

/// Convert byte offset to 1-based line/column.
fn byte_to_line_col(source: &str, byte: usize) -> (usize, usize) {
    let byte = byte.min(source.len());
    let line = source[..byte].matches('\n').count() + 1;
    let last_newline = source[..byte].rfind('\n');
    let col = match last_newline {
        Some(pos) => byte - pos,
        None => byte + 1,
    };
    (line, col)
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

/// Find the variable that a call expression's result is assigned to.
/// For multi-return (`a, b := f()`), `ret_idx` selects which return value's
/// variable to return.
fn result_variable_of_call(source: &str, call_byte: usize, ret_idx: usize) -> Option<String> {
    let end = call_byte.min(source.len());
    let before = &source[..end];
    // Look for `:=` or `=` at the end of the prefix, skipping `==` and `!=`.
    let assign = before
        .char_indices()
        .rev()
        .find(|&(i, c)| {
            if c != '=' {
                return false;
            }
            if i == 0 {
                return false;
            }
            let prev = before[..i]
                .chars()
                .last()
                .expect("i > 0 so before[..i] is non-empty");
            // Skip `==`, `!=`, `<=`, `>=` — only actual assignments.
            prev != '=' && prev != '!' && prev != '<' && prev != '>'
        })
        .map(|(i, _)| i)?;
    // Extract the LHS of the assignment from the current line.
    let line_start = before[..assign].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let lhs = before[line_start..assign].trim_end_matches(':').trim();
    // Split on `,` to handle multi-return.
    let vars: Vec<&str> = lhs.split(',').map(|v| v.trim()).collect();
    let var = vars.get(ret_idx).or_else(|| vars.last())?;
    if !var.is_empty() && var.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Some(var.to_string());
    }
    None
}

/// Which sink kinds does a variable reach in the TaintGraph (forward BFS)?
fn sink_kinds_reached_by_var(graph: &TaintGraph, var_name: &str) -> Vec<SinkKind> {
    let var_ids: Vec<TaintNodeId> = graph
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| matches!(n, TaintNode::Variable { name, .. } if name.as_ref() == var_name))
        .map(|(id, _)| id)
        .collect();
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
            if bfs_reaches_set(graph, &var_ids, sink_ids) {
                reached.push(sk);
            }
        }
    }
    reached
}

/// BFS from any start node to any target node.
fn bfs_reaches_set(graph: &TaintGraph, starts: &[TaintNodeId], targets: &[TaintNodeId]) -> bool {
    let mut adj: HashMap<TaintNodeId, Vec<TaintNodeId>> = HashMap::new();
    for edge in &graph.edges {
        adj.entry(edge.from).or_default().push(edge.to);
    }
    let mut visited = vec![false; graph.nodes.len()];
    let mut stack: Vec<TaintNodeId> = starts.to_vec();
    for &s in starts {
        if s < visited.len() {
            visited[s] = true;
        }
    }
    while let Some(current) = stack.pop() {
        if targets.contains(&current) {
            return true;
        }
        for &next in adj.get(&current).into_iter().flatten() {
            if next < visited.len() && !visited[next] {
                visited[next] = true;
                stack.push(next);
            }
        }
    }
    false
}

/// Emit findings for a cross-function taint flow.
#[allow(clippy::too_many_arguments)]
fn emit_inter_procedural_finding(
    file: &str,
    source: &str,
    _graph: &TaintGraph,
    _callee_name: &str,
    site: &taint::CallSite,
    sink_kinds: &[SinkKind],
    arg_text: &str,
    ctx: &ScanContext,
    out: &mut Vec<Finding>,
) {
    let (line, col) = byte_to_line_col(source, site.byte_range.start);
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
