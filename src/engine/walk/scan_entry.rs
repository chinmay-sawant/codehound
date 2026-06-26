//! Per-file scan: read → parse → detect → drop.

use std::path::Path;
use std::sync::Arc;

use crate::ast;
use crate::core::{LanguagePlugin, ParsedUnit, ScanContext};
use crate::engine::dependencies::extract_dependencies;
use crate::engine::ignore::{
    IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore,
    parse_inline_ignores,
};
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
use crate::engine::stats::{FileStats, ScanStats};
use crate::engine::timing::TimingCollector;
use crate::rules::Finding;

use super::analyze::analyze_parsed_unit;
use super::entry::ScanEntry;

/// Read, parse, and analyze a single file. Drops the parse tree before returning.
///
/// `pool` is reused across many files on the same worker thread (see [`scan_entries_parallel`]).
///
/// `project_root` and `module_prefix` (Go `module` directive) are used
/// to extract project-local dependency files after parsing; the
/// returned list is what gets written to the cache entry so a future
/// edit to a dependency can invalidate this file's cached findings.
///
/// On success, returns findings, cache key, source text, suppressed count,
/// per-file stats, dependency list, and a timing collector for this file.
pub(crate) fn scan_entry(
    registry: &Registry,
    ctx: &ScanContext,
    entry: &ScanEntry,
    pool: &mut ParsePool,
    project_root: &Path,
    module_prefix: Option<&str>,
) -> std::result::Result<
    (
        Vec<Finding>,
        String,
        Arc<str>,
        usize,
        ScanStats,
        Vec<String>,
        TimingCollector,
    ),
    ScanError,
> {
    let collect_stats = ctx.collect_stats();
    let mut timing = TimingCollector::new(collect_stats);
    let mut stats = ScanStats::default();

    let plugin = match registry.plugin_for_id(entry.language) {
        Some(p) => p,
        None => {
            stats.record_errored();
            return Err(ScanError {
                path: entry.path.clone(),
                kind: ScanErrorKind::Engine,
                message: format!("no plugin registered for {:?}", entry.language),
            });
        }
    };

    let bytes = {
        let idx = timing.start("file_read");
        let result = std::fs::read(&entry.path);
        timing.stop(idx);
        match result {
            Ok(b) => b,
            Err(e) => {
                stats.record_errored();
                return Err(ScanError {
                    path: entry.path.clone(),
                    kind: ScanErrorKind::Io,
                    message: format!("reading {}: {e}", entry.path.display()),
                });
            }
        }
    };

    let source = match String::from_utf8(bytes) {
        Ok(s) => Arc::from(s),
        Err(e) => {
            stats.record_errored();
            return Err(ScanError {
                path: entry.path.clone(),
                kind: ScanErrorKind::Encoding,
                message: format!("source is not valid UTF-8: {e}"),
            });
        }
    };

    let file_stats = FileStats::from_source(&source);

    let parser = pool.parser_for(plugin);
    let mut unit = {
        let idx = timing.start("tree_sitter_parse");
        let result = plugin.parse_with(parser, &entry.path, Arc::clone(&source));
        timing.stop(idx);
        match result {
            Ok(u) => u,
            Err(e) => {
                stats.record_errored();
                return Err(ScanError {
                    path: entry.path.clone(),
                    kind: ScanErrorKind::Parse,
                    message: format!("parsing {}: {e:#}", entry.path.display()),
                });
            }
        }
    };

    let file_ignore = parse_file_ignore(unit.source.as_ref());
    if !ctx.show_ignored && file_ignore.as_ref().is_some_and(IgnoreDirective::is_all) {
        let dependencies = extract_dependencies(&unit, project_root, module_prefix);
        stats.record_file(file_stats.bytes, file_stats.lines);
        return Ok((
            Vec::new(),
            unit.display_path.clone(),
            Arc::clone(&unit.source),
            0,
            stats,
            dependencies,
            timing,
        ));
    }

    // Precompute function spans once so attach_function_context can skip its
    // dedicated tree walk. Only languages that declare function_node_kinds
    // benefit (Go: function_declaration, method_declaration).
    let fn_kinds = plugin.function_node_kinds();
    if !fn_kinds.is_empty() {
        unit.function_spans = ast::collect_function_spans(unit.tree.root_node(), fn_kinds);
    }

    let det_idx = timing.start("detector_execution");
    let (mut findings, rules_executed) = analyze_parsed_unit(registry, ctx, &unit, &mut timing);
    timing.stop(det_idx);
    attach_function_context(&mut findings, plugin, &unit);
    let mut suppressed_count =
        apply_file_ignore(&mut findings, file_ignore.as_ref(), ctx.show_ignored);
    if file_ignore.is_none() {
        let inline_ignores = parse_inline_ignores(unit.source.as_ref());
        suppressed_count += apply_inline_ignores(&mut findings, &inline_ignores, ctx.show_ignored);
    }

    let dependencies = extract_dependencies(&unit, project_root, module_prefix);

    stats.record_file(file_stats.bytes, file_stats.lines);
    stats.findings_total = findings.len();
    stats.findings_suppressed = suppressed_count;
    stats.rules_executed = rules_executed;
    stats.detectors_loaded = registry.detector_count();

    Ok((
        findings,
        unit.display_path.clone(),
        Arc::clone(&unit.source),
        suppressed_count,
        stats,
        dependencies,
        timing,
    ))
}

/// Walk the unit's tree once to collect every function-like span, then attach
/// the enclosing function's byte/line range to each finding that falls inside
/// one. Findings whose line is outside every function (e.g. package-level
/// declarations, top-level statements) are left unchanged so the exporter
/// falls back to its snippet / small-window path.
pub(super) fn attach_function_context(
    findings: &mut [Finding],
    plugin: &dyn LanguagePlugin,
    unit: &ParsedUnit,
) {
    if findings.is_empty() {
        return;
    }

    let spans = if !unit.function_spans.is_empty() {
        &unit.function_spans
    } else {
        let kinds = plugin.function_node_kinds();
        if kinds.is_empty() {
            return;
        }
        // Fallback: compute on-demand (should not happen in normal scan path
        // since scan_entry precomputes them).
        let _ = kinds;
        return;
    };
    if spans.is_empty() {
        return;
    }

    for finding in findings.iter_mut() {
        if let Some(span) = ast::enclosing_function(spans, finding.line) {
            finding.function_start_byte = Some(span.start_byte);
            finding.function_end_byte = Some(span.end_byte);
            finding.function_start_line = Some(span.start_line);
            finding.function_end_line = Some(span.end_line);
        }
    }
}
