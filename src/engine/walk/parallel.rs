//! Parallel scan: read → parse → detect → drop, in chunks.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rayon::prelude::*;

use crate::Error;
use crate::core::ParsedUnit;
use crate::core::{LanguageId, ScanContext};
use crate::engine::cache::{CacheEntry, CacheLookup, CacheStore, content_hash};
use crate::engine::ignore::{apply_ignores, parse_file_ignore};
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
use crate::engine::stats::FileStats;
use crate::engine::stats::ScanStats;
use crate::engine::time::iso8601_utc_now;
use crate::rules::Finding;

use super::analyze::filter_findings;
use super::entry::ScanEntry;
use super::scan_entry::{PreloadedSource, ScanEntryResult, read_entry_utf8, scan_entry, scan_err};

/// Per-file outcome from a parallel scan: either findings or a structured error.
#[derive(Debug)]
pub(crate) enum ScanOutcome {
    Ok {
        findings: Vec<Finding>,
        cache_key: String,
        source: Arc<str>,
        content_hash: Option<String>,
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
    to_scan: Vec<(usize, Option<PreloadedSource>)>,
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
        &preflight.to_scan,
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

fn process_cache_hit(ctx: &ScanContext, cached: CacheEntry, source: Arc<str>) -> ScanOutcome {
    let cache_key = cached.file;
    let mut findings = cached.findings;
    filter_findings(ctx, &mut findings);
    let file_ignore = parse_file_ignore(source.as_ref());
    let _suppressed = apply_ignores(ctx, source.as_ref(), &mut findings, file_ignore.as_ref());
    let file_stats = FileStats::from_source(source.as_ref());
    let mut file_scan_stats = ScanStats::default();
    file_scan_stats.record_file(file_stats.bytes, file_stats.lines);
    ScanOutcome::Cached {
        findings,
        cache_key,
        source,
        stats: file_scan_stats,
    }
}

fn preflight_cache_hits(
    ctx: &ScanContext,
    entries: &[ScanEntry],
    cache: Option<&CacheStore>,
) -> PreflightResult {
    let total = entries.len();
    let mut to_scan = Vec::with_capacity(total);
    let mut cached_outcomes = Vec::new();
    let mut cache_hit_count = 0usize;

    let Some(cache) = cache else {
        to_scan.extend((0..entries.len()).map(|i| (i, None)));
        return PreflightResult {
            to_scan,
            cached_outcomes,
            cache_hit_count,
            cached_files: Vec::new(),
        };
    };

    let mut cached_files = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        if !cache.should_cache_path(entry.path.as_ref()) {
            to_scan.push((i, None));
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
                cached_outcomes.push(process_cache_hit(ctx, cached, source.clone()));
                cached_files.push(CachedFileInfo {
                    source,
                    display_path: rel,
                    language: entry.language,
                });
            }
            _ => to_scan.push((
                i,
                Some(PreloadedSource {
                    source,
                    content_hash: hash,
                }),
            )),
        }
    }

    PreflightResult {
        to_scan,
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
    to_scan: &[(usize, Option<PreloadedSource>)],
    project_root: &Path,
    module_prefix: Option<&str>,
) -> Vec<ScanOutcome> {
    to_scan
        .par_iter()
        .map_init(ParsePool::new, |pool, (i, preloaded)| {
            let entry = &entries[*i];
            let preloaded = preloaded.clone();
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scan_entry(
                    registry,
                    ctx,
                    entry,
                    pool,
                    project_root,
                    module_prefix,
                    preloaded,
                )
            }));
            match unwind {
                Ok(res) => match res {
                    Ok(ScanEntryResult {
                        findings,
                        cache_key,
                        source,
                        content_hash,
                        suppressed_count,
                        stats,
                        dependencies,
                    }) => ScanOutcome::Ok {
                        findings,
                        cache_key,
                        source,
                        content_hash,
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
                content_hash,
                suppressed_count: ignored,
                stats: file_stats,
                dependencies,
            } => {
                write_cache_on_miss(
                    cache,
                    &cache_key,
                    &source,
                    content_hash.as_deref(),
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
    precomputed_hash: Option<&str>,
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
    let hash = precomputed_hash
        .map(str::to_string)
        .unwrap_or_else(|| content_hash(source.as_ref()));
    let prior_hash = cache
        .manifest()
        .files
        .get(cache_key)
        .map(|m| m.content_hash.as_str());
    let hash_changed = prior_hash.map(|old| old != hash.as_str()).unwrap_or(false);
    let cached_at = iso8601_utc_now();
    if let Err(e) = cache.put(
        cache_key,
        &hash,
        dependencies,
        findings.to_vec(),
        &cached_at,
    ) {
        tracing::warn!(file = %cache_key, error = %e, "failed to write cache entry");
    }
    if hash_changed {
        rescan_files.push((cache_key.to_string(), true));
    }
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
