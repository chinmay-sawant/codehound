//! Per-file scan: read → parse → detect → drop.

use std::path::Path;
use std::sync::Arc;

use crate::ast;
use crate::core::{LanguagePlugin, ParsedUnit, ScanContext};
use crate::engine::dependencies::extract_dependencies;
use crate::engine::ignore::{IgnoreDirective, apply_ignores, parse_file_ignore};
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
use crate::engine::stats::{FileStats, ScanStats};
use crate::engine::timing;
use crate::rules::Finding;

use super::analyze::{analyze_parsed_unit, filter_findings};
use super::entry::ScanEntry;

/// Source text and content hash preloaded during cache preflight on a miss.
#[derive(Clone)]
pub(crate) struct PreloadedSource {
    pub source: Arc<str>,
    pub content_hash: String,
}

pub(super) fn scan_err(
    entry: &ScanEntry,
    kind: ScanErrorKind,
    message: impl Into<String>,
) -> ScanError {
    ScanError {
        path: entry.path.as_ref().to_path_buf(),
        kind,
        message: message.into(),
    }
}

/// Read file at `entry.path`, decode as UTF-8, return `(Arc<str>, display_path)`.
pub(super) fn read_entry_utf8(
    entry: &ScanEntry,
) -> Result<(std::sync::Arc<str>, String), ScanError> {
    let bytes = std::fs::read(&entry.path).map_err(|e| {
        scan_err(
            entry,
            ScanErrorKind::Io,
            format!("reading {}: {e}", entry.path.display()),
        )
    })?;
    let source = String::from_utf8(bytes).map_err(|e| {
        scan_err(
            entry,
            ScanErrorKind::Encoding,
            format!("source is not valid UTF-8: {e}"),
        )
    })?;
    Ok((
        std::sync::Arc::from(source),
        entry.path.display().to_string(),
    ))
}

pub(crate) struct ScanEntryResult {
    pub findings: Vec<Finding>,
    pub cache_key: String,
    pub source: Arc<str>,
    pub content_hash: Option<String>,
    pub suppressed_count: usize,
    pub stats: ScanStats,
    pub dependencies: Vec<String>,
}

struct ReadOutcome {
    source: Arc<str>,
    file_stats: FileStats,
}

fn read_entry_source(
    entry: &ScanEntry,
    stats: &mut ScanStats,
    preloaded: Option<&PreloadedSource>,
) -> Result<ReadOutcome, ScanError> {
    if let Some(preloaded) = preloaded {
        let file_stats = FileStats::from_source(&preloaded.source);
        return Ok(ReadOutcome {
            source: Arc::clone(&preloaded.source),
            file_stats,
        });
    }

    let idx = timing::global_start("file_read");
    let (source, _) = read_entry_utf8(entry).inspect_err(|_| {
        stats.record_errored();
    })?;
    timing::global_stop(idx);
    let file_stats = FileStats::from_source(&source);
    Ok(ReadOutcome { source, file_stats })
}

fn parse_entry_unit(
    entry: &ScanEntry,
    plugin: &dyn LanguagePlugin,
    pool: &mut ParsePool,
    source: Arc<str>,
    stats: &mut ScanStats,
) -> Result<ParsedUnit, ScanError> {
    let parser = pool.parser_for(plugin).map_err(|e| {
        stats.record_errored();
        scan_err(
            entry,
            ScanErrorKind::Parse,
            format!("configuring parser for {}: {e}", entry.path.display()),
        )
    })?;
    let idx = timing::global_start("tree_sitter_parse");
    let unit = plugin
        .parse_with(parser, &entry.path, Arc::clone(&source))
        .map_err(|e| {
            stats.record_errored();
            scan_err(
                entry,
                ScanErrorKind::Parse,
                format!("parsing {}: {e:#}", entry.path.display()),
            )
        })?;
    timing::global_stop(idx);
    Ok(unit)
}

fn analyze_parsed_entry(
    registry: &Registry,
    ctx: &ScanContext,
    plugin: &dyn LanguagePlugin,
    unit: &mut ParsedUnit,
    stats: &mut ScanStats,
    file_stats: FileStats,
    file_ignore: Option<IgnoreDirective>,
) -> (Vec<Finding>, usize) {
    let fn_kinds = plugin.function_node_kinds();
    if !fn_kinds.is_empty() {
        unit.function_spans = ast::collect_function_spans(unit.tree.root_node(), fn_kinds);
    }

    let det_idx = timing::global_start("detector_execution");
    let (mut findings, rules_executed) = analyze_parsed_unit(registry, ctx, unit);
    timing::global_stop(det_idx);
    filter_findings(ctx, &mut findings);
    attach_function_context(&mut findings, unit);
    let suppressed_count = apply_ignores(
        ctx,
        unit.source.as_ref(),
        &mut findings,
        file_ignore.as_ref(),
    );

    stats.record_file(file_stats.bytes, file_stats.lines);
    stats.findings_suppressed = suppressed_count;
    stats.rules_executed = rules_executed;
    stats.detectors_loaded = registry.detector_count();

    (findings, suppressed_count)
}

/// Read, parse, and analyze a single file. Drops the parse tree before returning.
///
/// `pool` is reused across many files on the same worker thread (see [`scan_entries_parallel`]).
///
/// `project_root` and `module_prefix` (Go `module` directive) are used
/// to extract project-local dependency files after parsing; the
/// returned list is what gets written to the cache entry so a future
/// edit to a dependency can invalidate this file's cached findings.
pub(crate) fn scan_entry(
    registry: &Registry,
    ctx: &ScanContext,
    entry: &ScanEntry,
    pool: &mut ParsePool,
    project_root: &Path,
    module_prefix: Option<&str>,
    preloaded: Option<PreloadedSource>,
) -> std::result::Result<ScanEntryResult, ScanError> {
    let mut stats = ScanStats::default();

    let plugin = match registry.plugin_for_id(entry.language) {
        Some(p) => p,
        None => {
            stats.record_errored();
            return Err(scan_err(
                entry,
                ScanErrorKind::Engine,
                format!("no plugin registered for {:?}", entry.language),
            ));
        }
    };

    let content_hash = preloaded.as_ref().map(|p| p.content_hash.clone());
    let ReadOutcome { source, file_stats } =
        read_entry_source(entry, &mut stats, preloaded.as_ref())?;
    let mut unit = parse_entry_unit(entry, plugin, pool, Arc::clone(&source), &mut stats)?;
    let dependencies = extract_dependencies(&unit, project_root, module_prefix);

    let file_ignore = parse_file_ignore(unit.source.as_ref());
    if !ctx.show_ignored && file_ignore.as_ref().is_some_and(IgnoreDirective::is_all) {
        stats.record_file(file_stats.bytes, file_stats.lines);
        return Ok(ScanEntryResult {
            findings: Vec::new(),
            cache_key: unit.display_path,
            source,
            content_hash,
            suppressed_count: 0,
            stats,
            dependencies,
        });
    }

    let (findings, suppressed_count) = analyze_parsed_entry(
        registry,
        ctx,
        plugin,
        &mut unit,
        &mut stats,
        file_stats,
        file_ignore,
    );

    Ok(ScanEntryResult {
        findings,
        cache_key: unit.display_path,
        source,
        content_hash,
        suppressed_count,
        stats,
        dependencies,
    })
}

/// Walk the unit's tree once to collect every function-like span, then attach
/// the enclosing function's byte/line range to each finding that falls inside
/// one. Findings whose line is outside every function (e.g. package-level
/// declarations, top-level statements) are left unchanged so the exporter
/// falls back to its snippet / small-window path.
pub(super) fn attach_function_context(findings: &mut [Finding], unit: &ParsedUnit) {
    if findings.is_empty() {
        return;
    }

    if unit.function_spans.is_empty() {
        return;
    }
    let spans = &unit.function_spans;
    for finding in findings.iter_mut() {
        if let Some(span) = ast::enclosing_function(spans, finding.line) {
            finding.function_start_byte = Some(span.start_byte);
            finding.function_end_byte = Some(span.end_byte);
            finding.function_start_line = Some(span.start_line);
            finding.function_end_line = Some(span.end_line);
        }
    }
}
