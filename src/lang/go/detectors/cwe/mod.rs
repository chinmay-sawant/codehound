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
    DetectorEvidence, Finding, RuleMetadata, RulePack, TaintHop, TaintSinkInfo, TaintSourceInfo,
    TimingGranularity,
};
use domains::*;
use facts::{FactBuildOpts, GoUnitFacts, build_go_unit_facts_with, build_taint_graph_for_facts};
use taint::{
    CallGraph, FunctionDecl, PackageIdentity, SharedText, SinkKind, TaintAnnotations, TaintGraph,
    TaintGraphIndex, TaintNode, TaintNodeId, TaintSymbolKey, build_import_map, build_index,
    detect_cwe_22_taint, detect_cwe_78_taint, detect_cwe_79_taint, detect_cwe_89_taint,
    detect_cwe_90_taint, detect_cwe_91_taint, forward_reaches_any_with_index,
    normalize_receiver_type, unsanitized_reaches_any_with_index,
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
    /// Directory + package-clause identity for same-package symbol resolution.
    package: PackageIdentity,
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

    fn pack(&self) -> RulePack {
        RulePack::Security
    }

    fn timing_granularity(&self) -> TimingGranularity {
        TimingGranularity::DetectorSpan
    }

    fn timing_label(&self) -> &'static str {
        "GoCweScan"
    }

    fn accumulate_state(&self, ctx: &ScanContext, unit: &ParsedUnit) {
        // Project state is only consumed by taint finalize.
        if !taint_is_enabled(ctx) {
            return;
        }
        let mut facts = build_go_unit_facts_with(unit, fact_build_opts(ctx));
        build_taint_graph_for_facts(&mut facts);
        let project_unit = make_project_unit(unit, &mut facts);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.units.push(project_unit);
    }

    fn requires_cache_state(&self, ctx: &ScanContext) -> bool {
        taint_is_enabled(ctx)
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
        let opts = fact_build_opts(ctx);
        let mut facts = build_go_unit_facts_with(unit, opts);
        if taint_is_enabled(ctx) {
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
        if taint_is_enabled(ctx) {
            let project_unit = make_project_unit(unit, &mut facts);
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.units.push(project_unit);
        }
    }

    fn finalize(&self, ctx: &ScanContext, out: &mut Vec<Finding>) {
        if !taint_is_enabled(ctx) {
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
        // Declarations keyed by package + receiver + name (not bare name alone).
        let mut decl_index: HashMap<TaintSymbolKey, usize> = HashMap::new();
        // Secondary bare-name index within a package for method-call resolution
        // when the receiver type is not known at the call site.
        let mut package_name_index: HashMap<(PackageIdentity, SharedText), Vec<TaintSymbolKey>> =
            HashMap::new();
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
            for (func_name, decl) in &unit.call_graph.declarations {
                let key = TaintSymbolKey::with_receiver(
                    unit.package.clone(),
                    decl.receiver_type.as_deref(),
                    Arc::clone(func_name),
                );
                decl_index.entry(key.clone()).or_insert(idx);
                package_name_index
                    .entry((unit.package.clone(), Arc::clone(func_name)))
                    .or_default()
                    .push(key);
            }
        }

        // Index project-wide lookups once before walking call sites. First
        // declaration wins within a package (stable after path sort above).
        let variable_indexes: Vec<VariableIndex> = per_file
            .iter()
            .map(|(_, graph, _, _)| build_variable_index(graph))
            .collect();
        let mut summary_index: HashMap<TaintSymbolKey, usize> = HashMap::new();
        for (file_idx, unit) in units.iter().enumerate() {
            let summaries = &per_file[file_idx].3;
            for name in summaries.keys() {
                let recv = unit
                    .call_graph
                    .declarations
                    .get(name.as_str())
                    .and_then(|d| d.receiver_type.as_deref());
                let key = TaintSymbolKey::with_receiver(
                    unit.package.clone(),
                    recv,
                    Arc::from(name.as_str()),
                );
                summary_index.entry(key).or_insert(file_idx);
            }
        }
        // Per-caller import map only: an import alias is package-local, so a
        // global prefix set would skip legitimate same-package selectors when
        // another file happens to import a package with that last segment.
        // Unqualified / same-package resolution never consults other packages.

        // Phase 2 + 3: Walk each file's call sites in place. Callee lookup is
        // restricted to the caller's package until import-path wiring exists.
        for (caller_idx, unit) in units.iter().enumerate() {
            let caller_path = unit.path.as_str();
            let caller_graph = &per_file[caller_idx].1;
            let caller_index = &per_file[caller_idx].2;
            let caller_variables = &variable_indexes[caller_idx];
            let caller_line_starts = &unit.line_starts;
            let caller_imports: HashSet<&str> =
                unit.import_map.keys().map(String::as_str).collect();

            for site in &unit.call_graph.sites {
                let raw_callee = site.callee.as_ref();
                // Skip package-qualified external calls (import alias prefix).
                // Same-package calls are bare identifiers; method calls use a
                // receiver variable, not an import alias.
                if site.is_method_call {
                    if let Some(dot) = raw_callee.rfind('.') {
                        let prefix = &raw_callee[..dot];
                        if caller_imports.contains(prefix) {
                            continue;
                        }
                    }
                }
                let callee_name = resolve_callee_name(raw_callee, site.is_method_call);
                let caller_decl = unit.call_graph.declarations.get(site.caller.as_ref());
                let callee_summary = find_same_package_summary(
                    &per_file,
                    &summary_index,
                    &package_name_index,
                    &decl_index,
                    &unit.package,
                    raw_callee,
                    &callee_name,
                    site.is_method_call,
                    caller_decl,
                );
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

/// Taint-only rules do not read the broad structural fact/index bundle.
/// Keep the structural default for every other rule; this small allowlist is
/// deliberately tied to the taint detectors' data requirements, not metadata.
fn is_taint_rule(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "CWE-22" | "CWE-78" | "CWE-79" | "CWE-89" | "CWE-90" | "CWE-91"
    )
}

fn taint_is_enabled(ctx: &ScanContext) -> bool {
    ctx.taint_enabled
        && self::metadata::GO_CWE_RULE_IDS
            .iter()
            .any(|id| ctx.allows(id) && is_taint_rule(id))
}

fn fact_build_opts(ctx: &ScanContext) -> FactBuildOpts {
    let needs_structural = GO_RULES
        .iter()
        .any(|(rule_id, _, _)| ctx.allows(rule_id) && !is_taint_rule(rule_id));
    FactBuildOpts::for_scan(taint_is_enabled(ctx), needs_structural)
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
    let path = unit.display_path.clone();
    let package = PackageIdentity::from_unit(&path, unit.source.as_ref());
    ProjectUnit {
        path,
        source: Arc::clone(&unit.source),
        line_starts: Arc::from(unit.line_starts.as_slice()),
        package,
        call_graph: facts.call_graph.clone().unwrap_or_default(),
        annotations: facts.taint.clone(),
        taint_graph: facts.taint_graph.take().unwrap_or_default(),
        import_map: build_import_map(unit),
    }
}

/// Resolve a callee summary strictly within `caller_package`.
///
/// Unqualified function calls match package + bare name with no receiver.
/// Method calls use the exact `PackageIdentity + receiver type + method name`
/// key when the call-site receiver type can be inferred (today: method body
/// calling through its own receiver parameter). When the receiver type is
/// unknown and more than one same-package receiver exposes the method name,
/// resolution is **declined** — a false negative is safer than selecting the
/// wrong taint summary. A unique receiver still resolves without inference.
/// Cross-package bare-name matches are intentionally refused until import
/// wiring exists.
#[allow(clippy::too_many_arguments)]
fn find_same_package_summary<'a>(
    per_file: &'a [(
        &str,
        TaintGraph,
        TaintGraphIndex,
        HashMap<String, taint::TaintSummary>,
    )],
    summary_index: &HashMap<TaintSymbolKey, usize>,
    package_name_index: &HashMap<(PackageIdentity, SharedText), Vec<TaintSymbolKey>>,
    decl_index: &HashMap<TaintSymbolKey, usize>,
    caller_package: &PackageIdentity,
    raw_callee: &str,
    bare_name: &str,
    is_method_call: bool,
    caller_decl: Option<&FunctionDecl>,
) -> Option<&'a taint::TaintSummary> {
    let bare: SharedText = Arc::from(bare_name);

    // Prefer exact free-function key for non-method (and as first try for bare).
    if !is_method_call {
        let fn_key = TaintSymbolKey::function(caller_package.clone(), Arc::clone(&bare));
        if let Some(summary) = summary_for_key(per_file, summary_index, &fn_key, bare_name) {
            return Some(summary);
        }
        // Also try raw callee text in case it already is the bare name with
        // a same-package declaration keyed that way (defensive).
        if raw_callee != bare_name {
            let raw_key = TaintSymbolKey::function(caller_package.clone(), Arc::from(raw_callee));
            if let Some(summary) = summary_for_key(per_file, summary_index, &raw_key, raw_callee) {
                return Some(summary);
            }
        }
        return None;
    }

    // Method call: same-package only. Prefer exact receiver key when known.
    let candidates = package_name_index.get(&(caller_package.clone(), Arc::clone(&bare)))?;

    if let Some(inferred) = infer_call_site_receiver_type(raw_callee, caller_decl) {
        let exact = TaintSymbolKey::with_receiver(
            caller_package.clone(),
            Some(inferred.as_str()),
            Arc::clone(&bare),
        );
        if let Some(summary) = summary_for_key(per_file, summary_index, &exact, bare_name) {
            return Some(summary);
        }
        if let Some(summary) = summary_from_decl(per_file, decl_index, &exact, bare_name) {
            return Some(summary);
        }
        // Inferred a concrete receiver but no matching summary — do not fall
        // back to a different receiver's summary.
        return None;
    }

    // No call-site receiver type: only resolve when the method name maps to a
    // single receiver type in the package. Multiple receivers → decline.
    let mut with_summary: Vec<&TaintSymbolKey> = candidates
        .iter()
        .filter(|key| summary_for_key(per_file, summary_index, key, bare_name).is_some())
        .collect();
    if with_summary.is_empty() {
        // Declarations may exist without a summary entry keyed the same way.
        with_summary = candidates
            .iter()
            .filter(|key| summary_from_decl(per_file, decl_index, key, bare_name).is_some())
            .collect();
    }
    if with_summary.is_empty() {
        return None;
    }

    let first_receiver = &with_summary[0].receiver;
    let unique = with_summary
        .iter()
        .all(|key| key.receiver == *first_receiver);
    if !unique {
        return None;
    }

    let key = with_summary[0];
    if let Some(summary) = summary_for_key(per_file, summary_index, key, bare_name) {
        return Some(summary);
    }
    summary_from_decl(per_file, decl_index, key, bare_name)
}

/// Infer the method call's receiver type when the callee is invoked on the
/// enclosing method's own receiver parameter (e.g. `func (h *Handler) F() {
/// h.Open(...) }` → `*Handler`). Full local-variable type inference is out of
/// scope; unknown receivers stay ambiguous.
fn infer_call_site_receiver_type(
    raw_callee: &str,
    caller_decl: Option<&FunctionDecl>,
) -> Option<String> {
    let recv_expr = raw_callee.rsplit_once('.')?.0.trim();
    if recv_expr.is_empty()
        || !recv_expr
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let raw = caller_decl?.receiver_type.as_deref()?;
    let normalized = normalize_receiver_type(raw);
    if normalized.is_empty() {
        return None;
    }
    let s = raw
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    let tokens: Vec<&str> = s.split_whitespace().collect();
    // "h *Handler" / "h Handler" → first token is the receiver parameter name.
    match tokens.as_slice() {
        [name, _, ..] if *name == recv_expr => Some(normalized),
        _ => None,
    }
}

fn summary_from_decl<'a>(
    per_file: &'a [(
        &str,
        TaintGraph,
        TaintGraphIndex,
        HashMap<String, taint::TaintSummary>,
    )],
    decl_index: &HashMap<TaintSymbolKey, usize>,
    key: &TaintSymbolKey,
    bare_name: &str,
) -> Option<&'a taint::TaintSummary> {
    let &file_idx = decl_index.get(key)?;
    per_file
        .get(file_idx)
        .and_then(|(_, _, _, summaries)| summaries.get(bare_name))
}

fn summary_for_key<'a>(
    per_file: &'a [(
        &str,
        TaintGraph,
        TaintGraphIndex,
        HashMap<String, taint::TaintSummary>,
    )],
    summary_index: &HashMap<TaintSymbolKey, usize>,
    key: &TaintSymbolKey,
    bare_name: &str,
) -> Option<&'a taint::TaintSummary> {
    let file_idx = *summary_index.get(key)?;
    per_file
        .get(file_idx)
        .and_then(|(_, _, _, summaries)| summaries.get(bare_name))
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
    use std::collections::HashSet;

    #[test]
    fn selected_taint_rules_skip_structural_facts() {
        let mut ctx = ScanContext {
            taint_enabled: true,
            ..Default::default()
        };
        ctx.only = Some(HashSet::from(["CWE-90".to_string()]));

        let opts = fact_build_opts(&ctx);
        assert!(opts.extract_taint);
        assert!(opts.extract_call_graph);
        assert!(!opts.extract_structural);

        ctx.only = Some(HashSet::from(["CWE-367".to_string()]));
        let opts = fact_build_opts(&ctx);
        assert!(opts.extract_structural);
        assert!(!opts.extract_taint);
    }

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

    #[test]
    fn resolve_callee_name_strips_method_receiver() {
        assert_eq!(resolve_callee_name("h.openFile", true), "openFile");
        assert_eq!(resolve_callee_name("openPath", false), "openPath");
    }

    #[test]
    fn infer_receiver_type_from_enclosing_method_param() {
        let decl = FunctionDecl {
            param_count: 0,
            is_method: true,
            receiver_type: Some(Arc::from("h *Handler")),
        };
        assert_eq!(
            infer_call_site_receiver_type("h.openFile", Some(&decl)).as_deref(),
            Some("*Handler")
        );
        // Different identifier — not the receiver param.
        assert_eq!(
            infer_call_site_receiver_type("other.openFile", Some(&decl)),
            None
        );
        // Free function caller has no receiver to propagate.
        let free = FunctionDecl {
            param_count: 1,
            is_method: false,
            receiver_type: None,
        };
        assert_eq!(
            infer_call_site_receiver_type("h.openFile", Some(&free)),
            None
        );
    }

    #[test]
    fn method_summary_declines_when_multiple_receivers_without_inference() {
        let pkg = PackageIdentity::from_unit("app/x.go", "package app\n");
        let handler_key =
            TaintSymbolKey::with_receiver(pkg.clone(), Some("h *Handler"), Arc::from("Open"));
        let store_key =
            TaintSymbolKey::with_receiver(pkg.clone(), Some("s *Store"), Arc::from("Open"));

        let mut summary_index: HashMap<TaintSymbolKey, usize> = HashMap::new();
        summary_index.insert(handler_key.clone(), 0);
        summary_index.insert(store_key.clone(), 1);

        let mut package_name_index: HashMap<(PackageIdentity, SharedText), Vec<TaintSymbolKey>> =
            HashMap::new();
        package_name_index.insert(
            (pkg.clone(), Arc::from("Open")),
            vec![handler_key, store_key],
        );

        let sink_summary = taint::TaintSummary {
            has_direct_sink: true,
            sink_kinds: vec![SinkKind::FileOpen],
            param_sources: vec![Some(true)],
            ..Default::default()
        };
        let safe_summary = taint::TaintSummary {
            param_sources: vec![Some(false)],
            ..Default::default()
        };
        let mut sink_map = HashMap::new();
        sink_map.insert("Open".to_string(), sink_summary);
        let mut safe_map = HashMap::new();
        safe_map.insert("Open".to_string(), safe_summary);
        let per_file = vec![
            (
                "app/handler.go",
                TaintGraph::default(),
                build_index(&TaintGraph::default()),
                sink_map,
            ),
            (
                "app/store.go",
                TaintGraph::default(),
                build_index(&TaintGraph::default()),
                safe_map,
            ),
        ];
        let decl_index: HashMap<TaintSymbolKey, usize> = HashMap::new();

        // Ambiguous free-function-style call site: must not pick first candidate.
        let ambiguous = find_same_package_summary(
            &per_file,
            &summary_index,
            &package_name_index,
            &decl_index,
            &pkg,
            "s.Open",
            "Open",
            true,
            None,
        );
        assert!(
            ambiguous.is_none(),
            "multiple receivers without inference must decline"
        );

        // Same receiver param as enclosing method → exact key (*Handler).
        let caller = FunctionDecl {
            param_count: 0,
            is_method: true,
            receiver_type: Some(Arc::from("h *Handler")),
        };
        let inferred = find_same_package_summary(
            &per_file,
            &summary_index,
            &package_name_index,
            &decl_index,
            &pkg,
            "h.Open",
            "Open",
            true,
            Some(&caller),
        );
        assert!(
            inferred.is_some_and(|s| s.has_direct_sink),
            "inferred *Handler must select the sink-bearing summary"
        );
    }
}
