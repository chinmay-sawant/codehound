//! Per-file scan: read → parse → detect → drop.

use std::path::Path;
use std::sync::Arc;

use crate::ast;
use crate::core::{LanguagePlugin, ParsedUnit, ScanContext};
use crate::engine::dependencies::extract_dependencies_with_registry;
use crate::engine::ignore::{IgnoreDirective, apply_ignores, parse_file_ignore};
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
use crate::engine::stats::ScanStats;
use crate::rules::Finding;

use super::analyze::{analyze_parsed_unit, filter_findings};
use super::entry::ScanEntry;

/// Source text and content hash preloaded during cache preflight on a miss.
#[derive(Clone)]
pub(crate) struct PreloadedSource {
    pub source: Arc<str>,
    pub content_hash: String,
}

pub(crate) struct ScanRequest<'a> {
    pub project_root: &'a Path,
    pub preloaded: Option<PreloadedSource>,
    pub collect_stats: bool,
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

/// Default max source file size for a scan (independent of cache eligibility).
/// Prevents multi-GB single-file OOM by default.
pub(crate) const DEFAULT_MAX_SCAN_FILE_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB

/// Read file at `entry.path`, decode as UTF-8, return `(Arc<str>, display_path)`.
pub(super) fn read_entry_utf8(
    entry: &ScanEntry,
) -> Result<(std::sync::Arc<str>, String), ScanError> {
    let meta = std::fs::metadata(&entry.path).map_err(|e| {
        scan_err(
            entry,
            ScanErrorKind::Io,
            format!("stat {}: {e}", entry.path.display()),
        )
    })?;
    if meta.len() > DEFAULT_MAX_SCAN_FILE_BYTES {
        return Err(scan_err(
            entry,
            ScanErrorKind::Io,
            format!(
                "skipping {}: file size {} bytes exceeds scan limit of {} bytes",
                entry.path.display(),
                meta.len(),
                DEFAULT_MAX_SCAN_FILE_BYTES
            ),
        ));
    }
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

#[derive(Debug)]
pub(crate) struct ScanEntryResult {
    pub findings: Vec<Finding>,
    pub cache_key: String,
    pub source: Arc<str>,
    pub content_hash: Option<String>,
    pub suppressed_count: usize,
    pub stats: ScanStats,
    pub dependencies: Vec<String>,
    pub timing: crate::engine::timing::TimingCollector,
}

struct ReadOutcome {
    source: Arc<str>,
    bytes: u64,
}

struct AnalysisOptions<'a> {
    file_ignore: Option<IgnoreDirective>,
    timing: &'a mut crate::engine::timing::TimingCollector,
}

fn read_entry_source(
    entry: &ScanEntry,
    stats: &mut ScanStats,
    preloaded: Option<&PreloadedSource>,
    timing: &mut crate::engine::timing::TimingCollector,
) -> Result<ReadOutcome, ScanError> {
    if let Some(preloaded) = preloaded {
        return Ok(ReadOutcome {
            source: Arc::clone(&preloaded.source),
            bytes: preloaded.source.len() as u64,
        });
    }

    let read = timing.measure("file_read", || read_entry_utf8(entry));
    let (source, _) = read.inspect_err(|_| {
        stats.record_errored();
    })?;
    let bytes = source.len() as u64;
    Ok(ReadOutcome { source, bytes })
}

fn parse_entry_unit(
    entry: &ScanEntry,
    plugin: &dyn LanguagePlugin,
    pool: &mut ParsePool,
    source: Arc<str>,
    stats: &mut ScanStats,
    timing: &mut crate::engine::timing::TimingCollector,
) -> Result<ParsedUnit, ScanError> {
    let parser = pool.parser_for(plugin).map_err(|e| {
        stats.record_errored();
        scan_err(
            entry,
            ScanErrorKind::Parse,
            format!("configuring parser for {}: {e}", entry.path.display()),
        )
    })?;
    let parsed = timing.measure("tree_sitter_parse", || {
        plugin.parse_with(parser, &entry.path, Arc::clone(&source))
    });
    let unit = parsed.map_err(|e| {
        stats.record_errored();
        scan_err(
            entry,
            ScanErrorKind::Parse,
            format!("parsing {}: {e:#}", entry.path.display()),
        )
    })?;
    Ok(unit)
}

fn analyze_parsed_entry(
    registry: &Registry,
    ctx: &ScanContext,
    plugin: &dyn LanguagePlugin,
    unit: &mut ParsedUnit,
    stats: &mut ScanStats,
    bytes: u64,
    options: AnalysisOptions<'_>,
) -> (Vec<Finding>, usize) {
    let fn_kinds = plugin.function_node_kinds();
    if !fn_kinds.is_empty() {
        unit.set_function_spans(ast::collect_function_spans(unit.tree.root_node(), fn_kinds));
    }

    // Per-detector / per-rule spans are recorded inside `analyze_parsed_unit`.
    // Avoid an outer `detector_execution` parent that double-counts those spans
    // in the top-10 percentage view.
    let (mut findings, rules_executed) = analyze_parsed_unit(registry, ctx, unit, options.timing);
    filter_findings(ctx, &mut findings);
    attach_function_context(&mut findings, unit);
    let suppressed_count = apply_ignores(
        ctx,
        unit.source.as_ref(),
        &mut findings,
        options.file_ignore.as_ref(),
    );

    stats.record_file(bytes, unit.line_starts.len() as u64);
    stats.findings_suppressed = suppressed_count;
    stats.rules_executed = rules_executed;
    stats.detectors_loaded = registry.detector_count();

    (findings, suppressed_count)
}

/// Read, parse, and analyze a single file. Drops the parse tree before returning.
///
/// `pool` is reused across many files on the same worker thread (see [`scan_entries_parallel`]).
///
/// `project_root` is the language-neutral base for dependency extraction after
/// parsing; plugins derive their own module data. The returned list is what
/// gets written to the cache entry so a future edit to a dependency can
/// invalidate this file's cached findings.
pub(crate) fn scan_entry(
    registry: &Registry,
    ctx: &ScanContext,
    entry: &ScanEntry,
    pool: &mut ParsePool,
    request: ScanRequest<'_>,
) -> std::result::Result<ScanEntryResult, ScanError> {
    let mut stats = ScanStats::default();
    let mut timing = crate::engine::timing::TimingCollector::new(request.collect_stats);

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

    let content_hash = request.preloaded.as_ref().map(|p| p.content_hash.clone());
    let ReadOutcome { source, bytes } =
        read_entry_source(entry, &mut stats, request.preloaded.as_ref(), &mut timing)?;
    let mut unit = parse_entry_unit(
        entry,
        plugin,
        pool,
        Arc::clone(&source),
        &mut stats,
        &mut timing,
    )?;
    let dependencies = extract_dependencies_with_registry(registry, &unit, request.project_root);

    let file_ignore = parse_file_ignore(unit.source.as_ref());
    if !ctx.show_ignored && file_ignore.as_ref().is_some_and(IgnoreDirective::is_all) {
        stats.record_file(bytes, unit.line_starts.len() as u64);
        return Ok(ScanEntryResult {
            findings: Vec::new(),
            cache_key: unit.display_path,
            source,
            content_hash,
            suppressed_count: 0,
            stats,
            dependencies,
            timing,
        });
    }

    let (findings, suppressed_count) = analyze_parsed_entry(
        registry,
        ctx,
        plugin,
        &mut unit,
        &mut stats,
        bytes,
        AnalysisOptions {
            file_ignore,
            timing: &mut timing,
        },
    );

    Ok(ScanEntryResult {
        findings,
        cache_key: unit.display_path,
        source,
        content_hash,
        suppressed_count,
        stats,
        dependencies,
        timing,
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
    attach_function_context_to_spans(findings, &unit.function_spans);
}

pub(crate) fn attach_function_context_to_spans(
    findings: &mut [Finding],
    spans: &[ast::FunctionSpan],
) {
    let mut span_order: Vec<usize> = (0..spans.len()).collect();
    span_order.sort_by_key(|&index| spans[index].start_line);
    let mut finding_order: Vec<usize> = (0..findings.len()).collect();
    finding_order.sort_by_key(|&index| findings[index].line);

    let mut active = Vec::new();
    let mut next_span = 0;
    for finding_index in finding_order {
        let line = findings[finding_index].line;
        while next_span < span_order.len() && spans[span_order[next_span]].start_line <= line {
            active.push(span_order[next_span]);
            next_span += 1;
        }
        active.retain(|&index| spans[index].end_line >= line);

        if let Some(&span_index) = active
            .iter()
            .max_by_key(|&&index| (spans[index].depth, index))
        {
            let span = spans[span_index];
            let finding = &mut findings[finding_index];
            finding.set_function_context(
                span.start_byte,
                span.end_byte,
                span.start_line,
                span.end_line,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::attach_function_context_to_spans;
    use crate::ast::FunctionSpan;
    use crate::rules::{Finding, FindingInputs, LineCol, Severity};

    fn finding(line: usize) -> Finding {
        Finding::new(FindingInputs::new(
            "TEST-1",
            "test",
            "file.go",
            LineCol::try_new(line, 1).expect("valid location"),
            "message",
            Severity::Info,
            Cow::Owned(Vec::new()),
        ))
    }

    #[test]
    fn function_context_sweep_selects_deepest_nested_span() {
        let spans = [
            FunctionSpan {
                start_byte: 0,
                end_byte: 100,
                start_line: 1,
                end_line: 20,
                depth: 0,
            },
            FunctionSpan {
                start_byte: 20,
                end_byte: 60,
                start_line: 5,
                end_line: 10,
                depth: 1,
            },
        ];
        let mut findings = vec![finding(7), finding(15), finding(30)];

        attach_function_context_to_spans(&mut findings, &spans);

        assert_eq!(findings[0].function_start_line, Some(5));
        assert_eq!(findings[1].function_start_line, Some(1));
        assert_eq!(findings[2].function_start_line, None);
    }

    #[test]
    fn function_context_sweep_preserves_finding_order() {
        let spans = [
            FunctionSpan {
                start_byte: 0,
                end_byte: 10,
                start_line: 1,
                end_line: 3,
                depth: 0,
            },
            FunctionSpan {
                start_byte: 20,
                end_byte: 30,
                start_line: 5,
                end_line: 7,
                depth: 0,
            },
        ];
        let mut findings = vec![finding(6), finding(2)];

        attach_function_context_to_spans(&mut findings, &spans);

        assert_eq!(findings[0].line, 6);
        assert_eq!(findings[0].function_start_line, Some(5));
        assert_eq!(findings[1].line, 2);
        assert_eq!(findings[1].function_start_line, Some(1));
    }
}
