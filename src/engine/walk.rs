//! Collect source paths and scan files (parallel parse + detect).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use rayon::prelude::*;

use crate::ast;
use crate::core::{LanguageId, LanguagePlugin, ParsedUnit, ScanContext};
use crate::engine::config::PathFilters;
use crate::engine::ignore::{
    IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore,
    parse_inline_ignores,
};
use crate::engine::language_filter::LanguageFilter;
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
use crate::engine::stats::{FileStats, ScanStats};
use crate::engine::timing::TimingCollector;
use crate::rules::Finding;

/// A source file queued for analysis.
#[derive(Debug, Clone)]
pub struct ScanEntry {
    pub path: PathBuf,
    pub language: LanguageId,
}

/// Walk paths and collect supported source files (no I/O beyond directory walk).
///
/// Honors `.gitignore`/`.ignore` (via `standard_filters(true)`) **and**
/// `.slopguardignore` if present at any walked root.
///
/// Returns the collected entries and the number of files skipped by
/// ignore/language/path filters.
pub fn collect_entries<I, P>(
    registry: &Registry,
    paths: I,
    lang_filter: &LanguageFilter,
    path_filters: &PathFilters,
) -> Result<(Vec<ScanEntry>, usize)>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut entries = Vec::new();
    let mut skipped = 0usize;

    for path in paths {
        let path = path.as_ref();
        let matcher = RootPathMatcher::new(path, path_filters)?;
        let mut builder = WalkBuilder::new(path);
        builder
            .standard_filters(true)
            .add_custom_ignore_filename(".slopguardignore");
        for entry in builder.build().filter_map(Result::ok) {
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            if !matcher.allows(entry.path()) {
                skipped += 1;
                continue;
            }
            let Some(plugin) = registry.plugin_for_path(entry.path()) else {
                skipped += 1;
                continue;
            };
            let language = plugin.id();
            if !lang_filter.allows(language) {
                skipped += 1;
                continue;
            }
            entries.push(ScanEntry {
                path: entry.path().to_path_buf(),
                language,
            });
        }
    }

    Ok((entries, skipped))
}

#[derive(Debug)]
struct RootPathMatcher {
    include: Option<Gitignore>,
    exclude: Option<Gitignore>,
    exclude_tests: bool,
}

impl RootPathMatcher {
    fn new(root: &Path, filters: &PathFilters) -> Result<Self> {
        let base = if root.is_dir() {
            root
        } else {
            root.parent().unwrap_or_else(|| Path::new("."))
        };

        Ok(Self {
            include: build_globset(base, &filters.include)?,
            exclude: build_globset(base, &filters.exclude)?,
            exclude_tests: filters.exclude_tests,
        })
    }

    fn allows(&self, path: &Path) -> bool {
        if self.exclude_tests {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.contains("_test") {
                    return false;
                }
            }
        }
        if let Some(include) = &self.include {
            if !include.matched(path, false).is_ignore() {
                return false;
            }
        }
        if let Some(exclude) = &self.exclude {
            if exclude.matched(path, false).is_ignore() {
                return false;
            }
        }
        true
    }
}

fn build_globset(base: &Path, patterns: &[String]) -> Result<Option<Gitignore>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GitignoreBuilder::new(base);
    for pattern in patterns {
        builder
            .add_line(None, pattern)
            .map_err(anyhow::Error::from)?;
    }
    Ok(Some(builder.build()?))
}

/// Read, parse, and analyze a single file. Drops the parse tree before returning.
///
/// `pool` is reused across many files on the same worker thread (see [`scan_entries_parallel`]).
///
/// On success, returns findings, cache key, source text, suppressed count,
/// per-file stats, and a timing collector for this file.
pub fn scan_entry(
    registry: &Registry,
    ctx: &ScanContext,
    entry: &ScanEntry,
    pool: &mut ParsePool,
) -> std::result::Result<
    (
        Vec<Finding>,
        String,
        Arc<str>,
        usize,
        ScanStats,
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
        stats.record_file(file_stats.bytes, file_stats.lines);
        return Ok((
            Vec::new(),
            unit.display_path.clone(),
            Arc::clone(&unit.source),
            0,
            stats,
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
        timing,
    ))
}

/// Walk the unit's tree once to collect every function-like span, then attach
/// the enclosing function's byte/line range to each finding that falls inside
/// one. Findings whose line is outside every function (e.g. package-level
/// declarations, top-level statements) are left unchanged so the exporter
/// falls back to its snippet / small-window path.
fn attach_function_context(
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

/// Run enabled detectors on an already-parsed unit.
///
/// Returns the findings and the number of detector invocations that actually
/// executed (used for scan statistics).
pub fn analyze_parsed_unit(
    registry: &Registry,
    ctx: &ScanContext,
    unit: &ParsedUnit,
    timing: &mut TimingCollector,
) -> (Vec<Finding>, usize) {
    let mut findings = Vec::new();
    let mut rules_executed = 0;
    let collect_detector_timing = ctx.collect_detector_timing();
    for &idx in registry.detector_indices(unit.language) {
        let det = registry.detector(idx);
        if !det.rule_ids().iter().any(|id| ctx.allows(id)) {
            continue;
        }
        rules_executed += 1;
        if collect_detector_timing {
            let name = det.rule_ids().first().copied().unwrap_or("detector");
            let span = timing.start(name);
            det.run(ctx, unit, &mut findings);
            timing.stop(span);
        } else {
            det.run(ctx, unit, &mut findings);
        }
    }
    (findings, rules_executed)
}

/// Run detectors **and** attach function-context ranges for a single unit.
/// This is the right entry point when the parsed unit is still alive (no
/// re-parse needed) — used by [`Analyzer::analyze_units`].
pub fn analyze_parsed_unit_with_context(
    registry: &Registry,
    ctx: &ScanContext,
    unit: &ParsedUnit,
) -> Vec<Finding> {
    let mut timing = TimingCollector::new(false);
    let (mut findings, _rules) = analyze_parsed_unit(registry, ctx, unit, &mut timing);
    if let Some(plugin) = registry.plugin_for_id(unit.language) {
        attach_function_context(&mut findings, plugin, unit);
    }
    findings
}

/// Per-file outcome from a parallel scan: either findings or a structured error.
#[derive(Debug)]
pub enum ScanOutcome {
    Ok {
        findings: Vec<Finding>,
        cache_key: String,
        source: Arc<str>,
        suppressed_count: usize,
        stats: ScanStats,
        timing: TimingCollector,
    },
    Err(ScanError),
}

/// Parallel scan: read → parse → detect → drop per file.
///
/// Per-file errors are collected and returned alongside findings — the scan
/// does **not** abort on the first bad file. Worker panics are caught and
/// surfaced as `ScanError::Engine` rather than tearing down the rayon
/// driver.
pub fn scan_entries_parallel(
    registry: &Registry,
    ctx: &ScanContext,
    entries: &[ScanEntry],
) -> Result<(
    Vec<Finding>,
    Vec<ScanError>,
    HashMap<String, Arc<str>>,
    usize,
    ScanStats,
    TimingCollector,
)> {
    let total = entries.len();
    let collect_stats = ctx.collect_stats();
    let outcomes: Vec<ScanOutcome> = entries
        .par_iter()
        .map_init(ParsePool::new, |pool, entry| {
            // `catch_unwind` so a panic in one worker (e.g. a tree-sitter
            // bug or a bug in a detector) does not bubble up and exit the
            // process with code 101. We surface it as a ScanError instead
            // so the run completes and the user can see which file failed.
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scan_entry(registry, ctx, entry, pool)
            }));
            match unwind {
                Ok(res) => match res {
                    Ok((findings, cache_key, source, suppressed_count, stats, timing)) => {
                        ScanOutcome::Ok {
                            findings,
                            cache_key,
                            source,
                            suppressed_count,
                            stats,
                            timing,
                        }
                    }
                    Err(e) => ScanOutcome::Err(e),
                },
                Err(payload) => {
                    let msg = panic_message(&payload);
                    tracing::error!(file = %entry.path.display(), "worker panicked: {msg}");
                    ScanOutcome::Err(ScanError {
                        path: entry.path.clone(),
                        kind: ScanErrorKind::Engine,
                        message: format!("worker panicked: {msg}"),
                    })
                }
            }
        })
        .collect();

    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut source_cache = HashMap::with_capacity(total);
    let mut suppressed_count = 0;
    let mut stats = ScanStats::default();
    let mut timing = TimingCollector::new(collect_stats);
    for outcome in outcomes {
        match outcome {
            ScanOutcome::Ok {
                findings: mut f,
                cache_key,
                source,
                suppressed_count: ignored,
                stats: file_stats,
                timing: file_timing,
            } => {
                findings.append(&mut f);
                source_cache.insert(cache_key, source);
                suppressed_count += ignored;
                stats.merge(&file_stats);
                timing.merge(&file_timing);
            }
            ScanOutcome::Err(e) => {
                errors.push(e);
                stats.record_errored();
            }
        }
    }

    tracing::debug!(
        findings = findings.len(),
        errors = errors.len(),
        total,
        "scan chunk complete"
    );

    Ok((
        findings,
        errors,
        source_cache,
        suppressed_count,
        stats,
        timing,
    ))
}

/// Best-effort message extraction from a `catch_unwind` payload. The payload
/// is typically `Box<dyn Any + Send>`, holding either `&'static str`,
/// `String`, or some other type from the panic site.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Per-thread scratch buffer for hot-path format-style string concatenation.
/// Detectors that build a needle string with `format!` (e.g. to check whether
/// the source contains a function call with a specific argument) can use
/// [`scratch_contains`] to avoid per-binding `String` allocations.
///
/// Each rayon worker thread has its own buffer; the buffer is reused
/// across all calls in that worker, so the steady-state cost is zero
/// allocations.
pub fn scratch_contains(source: &str, prefix: &str, dynamic: &str, suffix: &str) -> bool {
    use std::cell::RefCell;
    use std::fmt::Write;

    thread_local! {
        static BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
    }

    BUF.with_borrow_mut(|s| {
        s.clear();
        if write!(s, "{}{}{}", prefix, dynamic, suffix).is_err() {
            return false;
        }
        source.contains(s.as_str())
    })
}
