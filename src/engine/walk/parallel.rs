//! Parallel scan: read → parse → detect → drop, in chunks.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rayon::prelude::*;

use crate::Error;
use crate::core::ParsedUnit;
use crate::core::{LanguageId, ScanContext};
use crate::engine::cache::{CacheEntry, CacheLookup, CacheStore, content_hash};
use crate::engine::ignore::{
    IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore,
    parse_inline_ignores,
};
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
use crate::engine::stats::ScanStats;
use crate::rules::Finding;

use super::entry::ScanEntry;
use super::scan_entry::{ScanEntryResult, read_entry_utf8, scan_entry, scan_err};

/// Per-file outcome from a parallel scan: either findings or a structured error.
#[derive(Debug)]
pub(crate) enum ScanOutcome {
    Ok {
        findings: Vec<Finding>,
        cache_key: String,
        source: Arc<str>,
        language: LanguageId,
        suppressed_count: usize,
        stats: ScanStats,
        dependencies: Vec<String>,
    },
    Cached {
        findings: Vec<Finding>,
        cache_key: String,
        source: Arc<str>,
        stats: ScanStats,
    },
    Err(ScanError),
}

struct CachedFileInfo {
    source: Arc<str>,
    display_path: String,
    language: LanguageId,
}

struct PreflightResult {
    to_scan_indices: Vec<usize>,
    cached_outcomes: Vec<ScanOutcome>,
    cache_hit_count: usize,
    cached_files: Vec<CachedFileInfo>,
}

pub(crate) struct MergedScan {
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanError>,
    pub source_cache: HashMap<String, Arc<str>>,
    pub suppressed_count: usize,
    pub stats: ScanStats,
    pub rescan_files: Vec<(String, bool)>,
}

/// Parallel scan orchestrator: cache preflight → Rayon dispatch → merge.
pub(crate) fn scan_entries_parallel(
    registry: &Registry,
    ctx: &ScanContext,
    entries: &[ScanEntry],
    mut cache: Option<&mut CacheStore>,
    project_root: &Path,
    module_prefix: Option<&str>,
) -> Result<MergedScan, Error> {
    let total = entries.len();

    let preflight = preflight_cache_hits(ctx, entries, cache.as_deref());
    let scan_outcomes = dispatch_parallel_scan(
        registry,
        ctx,
        entries,
        &preflight.to_scan_indices,
        project_root,
        module_prefix,
    );
    let merged = merge_parallel_results(
        scan_outcomes,
        preflight.cached_outcomes,
        &mut cache,
        preflight.cache_hit_count,
        total,
    );

    // Accumulate cross-file detector state for cache-hit files
    // so finalize() can emit the same findings regardless of cache.
    if !preflight.cached_files.is_empty() {
        accumulate_state_for_cached(registry, ctx, &preflight.cached_files);
    }

    tracing::debug!(
        findings = merged.findings.len(),
        errors = merged.errors.len(),
        total,
        "scan chunk complete"
    );

    Ok(merged)
}

fn apply_cached_ignores(ctx: &ScanContext, source: &str, findings: &mut Vec<Finding>) {
    let file_ignore = parse_file_ignore(source);
    if !ctx.show_ignored && file_ignore.as_ref().is_some_and(IgnoreDirective::is_all) {
        findings.clear();
        return;
    }
    apply_file_ignore(findings, file_ignore.as_ref(), ctx.show_ignored);
    if file_ignore.is_none() {
        let inline_ignores = parse_inline_ignores(source);
        apply_inline_ignores(findings, &inline_ignores, ctx.show_ignored);
    }
}

fn process_cache_hit(
    ctx: &ScanContext,
    cached: CacheEntry,
    source: Arc<str>,
    _fallback_language: LanguageId,
) -> ScanOutcome {
    let cache_key = cached.file;
    let mut findings = filter_cached_findings(ctx, cached.findings);
    apply_cached_ignores(ctx, source.as_ref(), &mut findings);
    let mut file_stats = ScanStats::default();
    file_stats.record_file(source.len() as u64, bytecount_lines(&source) as u64);
    ScanOutcome::Cached {
        findings,
        cache_key,
        source,
        stats: file_stats,
    }
}

fn preflight_cache_hits(
    ctx: &ScanContext,
    entries: &[ScanEntry],
    cache: Option<&CacheStore>,
) -> PreflightResult {
    let total = entries.len();
    let mut to_scan_indices = Vec::with_capacity(total);
    let mut cached_outcomes = Vec::new();
    let mut cache_hit_count = 0usize;

    let Some(cache) = cache else {
        to_scan_indices.extend(0..entries.len());
        return PreflightResult {
            to_scan_indices,
            cached_outcomes,
            cache_hit_count,
            cached_files: Vec::new(),
        };
    };

    let mut cached_files = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        if !cache.should_cache_path(entry.path.as_ref()) {
            to_scan_indices.push(i);
            continue;
        }
        let (source, rel) = match read_entry_utf8(entry) {
            Ok(v) => v,
            Err(e) => {
                cached_outcomes.push(ScanOutcome::Err(e));
                continue;
            }
        };
        let hash = content_hash(&source);
        match cache.lookup(&rel, &hash) {
            CacheLookup::Hit(cached) => {
                cache_hit_count += 1;
                cached_outcomes.push(process_cache_hit(
                    ctx,
                    cached,
                    source.clone(),
                    entry.language,
                ));
                cached_files.push(CachedFileInfo {
                    source,
                    display_path: rel,
                    language: entry.language,
                });
            }
            _ => to_scan_indices.push(i),
        }
    }

    PreflightResult {
        to_scan_indices,
        cached_outcomes,
        cache_hit_count,
        cached_files,
    }
}

/// Re-parse cache-hit files and run detectors to populate cross-file
/// detector state (e.g. call graphs for taint analysis) that `finalize()`
/// needs. The generated per-file findings are discarded — cached findings
/// are used instead.
fn accumulate_state_for_cached(registry: &Registry, ctx: &ScanContext, files: &[CachedFileInfo]) {
    let mut pool = ParsePool::new();
    for info in files {
        let Some(plugin) = registry.plugin_for_id(info.language) else {
            continue;
        };
        let parser = match pool.parser_for(plugin) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let tree = match parser.parse(info.source.as_bytes(), None) {
            Some(t) => t,
            None => continue,
        };
        let unit = ParsedUnit {
            language: info.language,
            path: std::path::PathBuf::from(&info.display_path),
            display_path: info.display_path.clone(),
            source: info.source.clone(),
            tree,
            line_starts: crate::ast::compute_line_starts(&info.source),
            function_spans: Vec::new(),
        };
        // Run only `accumulate_state` (no per-file rule execution) so
        // cross-file analysis in `finalize()` has the same state regardless
        // of cache status.
        for &idx in registry.detector_indices(info.language) {
            registry.detector(idx).accumulate_state(ctx, &unit);
        }
    }
}

fn dispatch_parallel_scan(
    registry: &Registry,
    ctx: &ScanContext,
    entries: &[ScanEntry],
    to_scan_indices: &[usize],
    project_root: &Path,
    module_prefix: Option<&str>,
) -> Vec<ScanOutcome> {
    to_scan_indices
        .par_iter()
        .map_init(ParsePool::new, |pool, &i| {
            let entry = &entries[i];
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scan_entry(registry, ctx, entry, pool, project_root, module_prefix)
            }));
            match unwind {
                Ok(res) => match res {
                    Ok(ScanEntryResult {
                        findings,
                        cache_key,
                        source,
                        suppressed_count,
                        stats,
                        dependencies,
                    }) => ScanOutcome::Ok {
                        findings,
                        cache_key,
                        source,
                        language: entry.language,
                        suppressed_count,
                        stats,
                        dependencies,
                    },
                    Err(e) => ScanOutcome::Err(e),
                },
                Err(payload) => {
                    let msg = panic_message(&payload);
                    tracing::error!(file = %entry.path.display(), "worker panicked: {msg}");
                    ScanOutcome::Err(scan_err(
                        entry,
                        ScanErrorKind::Engine,
                        format!("worker panicked: {msg}"),
                    ))
                }
            }
        })
        .collect()
}

fn merge_parallel_results(
    scan_outcomes: Vec<ScanOutcome>,
    cached_outcomes: Vec<ScanOutcome>,
    cache: &mut Option<&mut CacheStore>,
    cache_hit_count: usize,
    total: usize,
) -> MergedScan {
    let mut merged = MergedScan {
        findings: Vec::new(),
        errors: Vec::new(),
        source_cache: HashMap::with_capacity(total),
        suppressed_count: 0,
        stats: ScanStats::default(),
        rescan_files: Vec::new(),
    };

    for outcome in scan_outcomes {
        match outcome {
            ScanOutcome::Ok {
                findings: mut f,
                cache_key,
                source,
                language,
                suppressed_count: ignored,
                stats: file_stats,
                dependencies,
            } => {
                write_cache_on_miss(
                    cache,
                    &cache_key,
                    &source,
                    language,
                    &f,
                    &dependencies,
                    &mut merged.rescan_files,
                );
                merged.findings.append(&mut f);
                merged.source_cache.insert(cache_key, source);
                merged.suppressed_count += ignored;
                merged.stats.merge(&file_stats);
            }
            ScanOutcome::Err(e) => {
                merged.errors.push(e);
                merged.stats.record_errored();
            }
            ScanOutcome::Cached { .. } => {}
        }
    }

    for outcome in cached_outcomes {
        match outcome {
            ScanOutcome::Cached {
                findings: mut f,
                cache_key,
                source,
                stats: file_stats,
                ..
            } => {
                merged.findings.append(&mut f);
                merged.source_cache.insert(cache_key, source);
                merged.stats.merge(&file_stats);
            }
            ScanOutcome::Err(e) => {
                merged.errors.push(e);
                merged.stats.record_errored();
            }
            _ => {}
        }
    }

    merged.stats.cache_hits = cache_hit_count;
    merged.stats.cache_misses = merged.stats.files_scanned.saturating_sub(cache_hit_count);
    merged
}

fn write_cache_on_miss(
    cache: &mut Option<&mut CacheStore>,
    cache_key: &str,
    source: &Arc<str>,
    language: LanguageId,
    findings: &[Finding],
    dependencies: &[String],
    rescan_files: &mut Vec<(String, bool)>,
) {
    let Some(cache) = cache.as_deref_mut() else {
        return;
    };
    if !cache.should_cache_bytes(source.len() as u64) {
        cache.invalidate_file(cache_key);
        return;
    }
    let hash = content_hash(source);
    let mtime = mtime_of(cache_key);
    let prior_hash = cache
        .manifest()
        .files
        .get(cache_key)
        .map(|m| m.content_hash.as_str());
    let hash_changed = prior_hash.map(|old| old != hash.as_str()).unwrap_or(false);
    let entry = CacheEntry {
        schema_version: crate::engine::cache::CACHE_VERSION,
        file: cache_key.to_string(),
        content_hash: hash,
        mtime_secs: mtime.0,
        mtime_nanos: mtime.1,
        language: language.as_str().to_string(),
        findings: findings.to_vec(),
        dependencies: dependencies.to_vec(),
        cached_at: crate::engine::time::iso8601_utc_now(),
    };
    if let Err(e) = cache.put(entry) {
        tracing::warn!(file = %cache_key, error = %e, "failed to write cache entry");
    }
    if hash_changed {
        rescan_files.push((cache_key.to_string(), true));
    }
}

fn filter_cached_findings(ctx: &ScanContext, findings: Vec<Finding>) -> Vec<Finding> {
    if findings.is_empty() {
        return findings;
    }
    findings
        .into_iter()
        .filter_map(|mut f| {
            if ctx.allows(f.rule_id) {
                ctx.apply_finding_overrides(&mut f);
                Some(f)
            } else {
                None
            }
        })
        .collect()
}

fn mtime_of(rel: &str) -> (u64, u32) {
    match std::fs::metadata(rel) {
        Ok(m) => match m.modified() {
            Ok(t) => match t.duration_since(std::time::SystemTime::UNIX_EPOCH) {
                Ok(d) => (d.as_secs(), d.subsec_nanos()),
                Err(_) => (0, 0),
            },
            Err(_) => (0, 0),
        },
        Err(_) => (0, 0),
    }
}

fn bytecount_lines(s: &str) -> usize {
    if s.is_empty() {
        return 0;
    }
    s.bytes().filter(|b| *b == b'\n').count() + 1
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}
