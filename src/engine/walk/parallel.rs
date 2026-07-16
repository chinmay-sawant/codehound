//! Parallel scan: read → parse → detect → drop, in chunks.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use rayon::prelude::*;

use crate::Error;
use crate::core::ParsedUnit;
use crate::core::{LanguageId, ScanContext};
use crate::engine::cache::{CacheEntry, CacheLookup, CacheSession, CacheStore, content_hash};
use crate::engine::ignore::{apply_ignores, parse_file_ignore};
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
use crate::engine::stats::FileStats;
use crate::engine::stats::ScanStats;
use crate::engine::time::iso8601_utc_now;
use crate::engine::timing::TimingCollector;
use crate::rules::Finding;

use super::analyze::filter_findings;
use super::entry::ScanEntry;
use super::scan_entry::{
    PreloadedSource, ScanEntryResult, ScanRequest, read_entry_utf8, scan_entry, scan_err,
};

/// Per-file outcome from a parallel scan: either findings or a structured error.
#[derive(Debug)]
pub(crate) enum ScanOutcome {
    Fresh(ScanEntryResult),
    Cached {
        findings: Vec<Finding>,
        cache_key: String,
        source: Arc<str>,
        stats: ScanStats,
        suppressed_count: usize,
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
    pub timing: TimingCollector,
}

/// Parallel scan orchestrator: cache preflight → Rayon dispatch → merge.
pub(crate) fn scan_entries_parallel(
    registry: &Registry,
    ctx: &ScanContext,
    entries: &[ScanEntry],
    mut cache: Option<&mut CacheSession<'_>>,
    project_root: &Path,
    module_prefix: Option<&str>,
    collect_stats: bool,
) -> Result<MergedScan, Error> {
    let total = entries.len();

    let preflight =
        preflight_cache_hits(ctx, entries, cache.as_deref().map(CacheSession::as_store));
    let scan_outcomes = dispatch_parallel_scan(
        registry,
        ctx,
        entries,
        &preflight.to_scan,
        project_root,
        module_prefix,
        collect_stats,
    );
    let mut merged = merge_parallel_results(
        scan_outcomes,
        preflight.cached_outcomes,
        &mut cache,
        preflight.cache_hit_count,
        total,
        ctx.retain_sources,
        collect_stats,
    );

    // Accumulate cross-file detector state for cache-hit files when a
    // detector explicitly opts into the capability, so finalize() can emit
    // the same findings regardless of cache without reparsing for stateless
    // detectors.
    let needs_cache_state = registry
        .detectors()
        .iter()
        .any(|detector| detector.requires_cache_state(ctx));
    if needs_cache_state && !preflight.cached_files.is_empty() {
        merged.errors.extend(accumulate_state_for_cached(
            registry,
            ctx,
            &preflight.cached_files,
        ));
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
    let suppressed_count = cached.suppressed_count;
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
        suppressed_count,
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

    // Phase 1: read + hash every eligible file concurrently; collect provisional
    // hits/misses. Cache lookups are read-only against the store, so Rayon is safe.
    struct Provisional {
        index: usize,
        source: Arc<str>,
        rel: String,
        hash: String,
        hit: Option<CacheEntry>,
        language: LanguageId,
    }

    enum Phase1Item {
        SkipScan(usize),
        Err(ScanError),
        Ready(Provisional),
    }

    let phase1: Vec<Phase1Item> = entries
        .par_iter()
        .enumerate()
        .map(|(i, entry)| {
            if !cache.should_cache_path(entry.path.as_ref()) {
                return Phase1Item::SkipScan(i);
            }
            let (source, rel) = match read_entry_utf8(entry) {
                Ok(v) => v,
                Err(e) => return Phase1Item::Err(e),
            };
            let rel = crate::engine::path_identity::normalize_project_path(&rel);
            let hash = content_hash(&source);
            let hit = match cache.lookup(&rel, &hash) {
                CacheLookup::Hit(cached) => Some(cached),
                _ => None,
            };
            Phase1Item::Ready(Provisional {
                index: i,
                source,
                rel,
                hash,
                hit,
                language: entry.language,
            })
        })
        .collect();

    let mut provisional: Vec<Provisional> = Vec::with_capacity(total);
    let mut dirty: std::collections::HashSet<String> = std::collections::HashSet::new();
    for item in phase1 {
        match item {
            Phase1Item::SkipScan(i) => to_scan.push((i, None)),
            Phase1Item::Err(e) => cached_outcomes.push(ScanOutcome::Err(e)),
            Phase1Item::Ready(p) => {
                if p.hit.is_none() {
                    dirty.insert(p.rel.clone());
                }
                provisional.push(p);
            }
        }
    }

    // Phase 2: same-scan cascade — reverse-dep fixpoint through the manifest.
    // If A depends on B and B is dirty, force A dirty so we re-parse A now
    // (not only on the next scan).
    cache.expand_dirty_fixpoint(&mut dirty);

    // Phase 3: emit hits only when not dirty; otherwise force re-scan.
    let mut cached_files = Vec::new();
    for p in provisional {
        if let Some(cached) = p.hit {
            if !dirty.contains(&p.rel) {
                cache_hit_count += 1;
                cached_outcomes.push(process_cache_hit(ctx, cached, p.source.clone()));
                cached_files.push(CachedFileInfo {
                    source: p.source,
                    display_path: p.rel,
                    language: p.language,
                });
                continue;
            }
        }
        to_scan.push((
            p.index,
            Some(PreloadedSource {
                source: p.source,
                content_hash: p.hash,
            }),
        ));
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
fn accumulate_state_for_cached(
    registry: &Registry,
    ctx: &ScanContext,
    files: &[CachedFileInfo],
) -> Vec<ScanError> {
    let mut errors = Vec::new();
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
            if let Some(detector) = registry.detector(idx) {
                if !detector.requires_cache_state(ctx) {
                    continue;
                }
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    detector.accumulate_state(ctx, &unit);
                }));
                if let Err(payload) = result {
                    reset_detector_after_panic(detector);
                    errors.push(ScanError {
                        path: unit.path.clone(),
                        kind: ScanErrorKind::Engine,
                        message: format!(
                            "cached detector state accumulation panicked: {}",
                            panic_message(&payload)
                        ),
                    });
                }
            }
        }
    }
    errors
}

fn reset_detector_after_panic(detector: &dyn crate::core::Detector) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| detector.reset_state())).is_err() {
        tracing::error!("detector reset_state panicked while recovering from a detector panic");
    }
}

fn dispatch_parallel_scan(
    registry: &Registry,
    ctx: &ScanContext,
    entries: &[ScanEntry],
    to_scan: &[(usize, Option<PreloadedSource>)],
    project_root: &Path,
    module_prefix: Option<&str>,
    collect_stats: bool,
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
                    ScanRequest {
                        project_root,
                        module_prefix,
                        preloaded,
                        collect_stats,
                    },
                )
            }));
            match unwind {
                Ok(res) => match res {
                    Ok(result) => ScanOutcome::Fresh(result),
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
    cache: &mut Option<&mut CacheSession<'_>>,
    cache_hit_count: usize,
    total: usize,
    retain_sources: bool,
    collect_stats: bool,
) -> MergedScan {
    let mut merged = MergedScan {
        findings: Vec::new(),
        errors: Vec::new(),
        source_cache: if retain_sources {
            HashMap::with_capacity(total)
        } else {
            HashMap::new()
        },
        suppressed_count: 0,
        stats: ScanStats::default(),
        rescan_files: Vec::new(),
        timing: TimingCollector::new(collect_stats),
    };

    for outcome in scan_outcomes {
        match outcome {
            ScanOutcome::Fresh(mut result) => {
                write_cache_on_miss(cache, &result, &mut merged.rescan_files);
                merged.timing.merge_owned(result.timing);
                append_file_contribution(
                    &mut merged,
                    &mut result.findings,
                    result.cache_key,
                    result.source,
                    &result.stats,
                    result.suppressed_count,
                    retain_sources,
                );
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
                suppressed_count,
            } => {
                append_file_contribution(
                    &mut merged,
                    &mut f,
                    cache_key,
                    source,
                    &file_stats,
                    suppressed_count,
                    retain_sources,
                );
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

fn append_file_contribution(
    merged: &mut MergedScan,
    findings: &mut Vec<Finding>,
    cache_key: String,
    source: Arc<str>,
    stats: &ScanStats,
    suppressed_count: usize,
    retain_sources: bool,
) {
    merged.findings.append(findings);
    if retain_sources {
        merged.source_cache.insert(cache_key, source);
    }
    merged.suppressed_count += suppressed_count;
    merged.stats.merge(stats);
}

fn write_cache_on_miss(
    cache: &mut Option<&mut CacheSession<'_>>,
    result: &ScanEntryResult,
    rescan_files: &mut Vec<(String, bool)>,
) {
    let Some(session) = cache.as_deref_mut() else {
        return;
    };
    if !session.should_cache_bytes(result.source.len() as u64) {
        session.invalidate_file(&result.cache_key);
        return;
    }
    let hash = result
        .content_hash
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| content_hash(result.source.as_ref()));
    let prior_hash = session
        .manifest()
        .files
        .get(&result.cache_key)
        .map(|m| m.content_hash.as_str());
    let hash_changed = prior_hash.map(|old| old != hash.as_str()).unwrap_or(false);
    let cached_at = iso8601_utc_now();
    if let Err(e) = session.put_with_suppressed_count_borrowed(
        &result.cache_key,
        &hash,
        &result.dependencies,
        &result.findings,
        result.suppressed_count,
        &cached_at,
    ) {
        tracing::warn!(file = %result.cache_key, error = %e, "failed to write cache entry");
    }
    if hash_changed {
        rescan_files.push((result.cache_key.clone(), true));
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
