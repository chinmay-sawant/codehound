//! Parallel scan: read → parse → detect → drop, in chunks.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use rayon::prelude::*;

use crate::core::{LanguageId, ScanContext};
use crate::engine::cache::{CacheEntry, CacheStore, content_hash};
use crate::engine::ignore::{
    IgnoreDirective, apply_file_ignore, apply_inline_ignores, parse_file_ignore,
    parse_inline_ignores,
};
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
use crate::engine::stats::ScanStats;
use crate::engine::timing::TimingCollector;
use crate::rules::Finding;

use super::entry::ScanEntry;
use super::scan_entry::scan_entry;

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
        timing: TimingCollector,
    },
    Cached {
        findings: Vec<Finding>,
        cache_key: String,
        source: Arc<str>,
        #[allow(dead_code)]
        language: LanguageId,
        stats: ScanStats,
    },
    Err(ScanError),
}

/// Parallel scan: read → parse → detect → drop per file.
///
/// Per-file errors are collected and returned alongside findings — the scan
/// does **not** abort on the first bad file. Worker panics are caught and
/// surfaced as `ScanError::Engine` rather than tearing down the rayon
/// driver.
///
/// When `cache` is `Some`, each entry is first hashed and looked up in
/// the cache. On a hit, the cached findings are returned and the file
/// is not re-parsed; on a miss, the file is scanned normally and a new
/// cache entry is written.
///
/// `project_root` and `module_prefix` are passed through to
/// [`scan_entry`] so dependency extraction has the project context it
/// needs. The returned `Vec<(String, bool)>` is the list of files
/// that were re-parsed (cache misses) paired with a flag that
/// indicates whether the content hash actually changed. The analyzer
/// uses the `true` entries to cascade invalidation: any manifest
/// entry that listed one of these files as a dependency must be
/// dropped, because its findings may now be stale.
pub(crate) fn scan_entries_parallel(
    registry: &Registry,
    ctx: &ScanContext,
    entries: &[ScanEntry],
    mut cache: Option<&mut CacheStore>,
    project_root: &Path,
    module_prefix: Option<&str>,
) -> Result<(
    Vec<Finding>,
    Vec<ScanError>,
    HashMap<String, Arc<str>>,
    usize,
    ScanStats,
    TimingCollector,
    Vec<(String, bool)>,
)> {
    let total = entries.len();
    let collect_stats = ctx.collect_stats();

    // Split the entries into a "scan" pool (cache misses + no cache)
    // and a "cache hit" pool. Cache hits are processed in parallel
    // without touching the cache (read-only), so we don't need to
    // serialize them through the cache mutex.
    let mut to_scan: Vec<ScanEntry> = Vec::with_capacity(total);
    let mut cached_outcomes: Vec<ScanOutcome> = Vec::new();
    let mut scanned_files_for_prune: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(total);
    let mut cache_hit_count: usize = 0;

    if let Some(cache) = cache.as_deref() {
        for entry in entries {
            scanned_files_for_prune.insert(entry.path.display().to_string());
            let bytes = match std::fs::read(&entry.path) {
                Ok(b) => b,
                Err(e) => {
                    cached_outcomes.push(ScanOutcome::Err(ScanError {
                        path: entry.path.clone(),
                        kind: ScanErrorKind::Io,
                        message: format!("reading {}: {e}", entry.path.display()),
                    }));
                    continue;
                }
            };
            let source = match String::from_utf8(bytes.clone()) {
                Ok(s) => Arc::from(s),
                Err(e) => {
                    cached_outcomes.push(ScanOutcome::Err(ScanError {
                        path: entry.path.clone(),
                        kind: ScanErrorKind::Encoding,
                        message: format!("source is not valid UTF-8: {e}"),
                    }));
                    continue;
                }
            };
            let hash = content_hash(&source);
            let rel = entry.path.display().to_string();
            match cache.lookup(&rel, &hash) {
                crate::engine::cache::CacheLookup::Hit(entry) => {
                    cache_hit_count += 1;
                    let language = LanguageId::parse(&entry.language).unwrap_or(LanguageId::Go);
                    // Re-apply inline-ignore and file-ignore on the
                    // cached findings. The source is already in
                    // memory for the hash check, so the cost is
                    // essentially free. Findings that the user has
                    // since marked with `// slopguard-ignore: RULE`
                    // or `// slopguard-ignore-file` are dropped
                    // (unless `--show-ignored` is set, in which
                    // case they are kept and flagged as suppressed).
                    let mut findings = filter_cached_findings(ctx, entry.findings);
                    let file_ignore = parse_file_ignore(&source);
                    if !ctx.show_ignored
                        && file_ignore.as_ref().is_some_and(IgnoreDirective::is_all)
                    {
                        // The whole file is ignored — drop every
                        // cached finding.
                        findings.clear();
                    } else {
                        let mut suppressed = apply_file_ignore(
                            &mut findings,
                            file_ignore.as_ref(),
                            ctx.show_ignored,
                        );
                        if file_ignore.is_none() {
                            let inline_ignores = parse_inline_ignores(&source);
                            suppressed += apply_inline_ignores(
                                &mut findings,
                                &inline_ignores,
                                ctx.show_ignored,
                            );
                        }
                        // `suppressed` is a per-file count; the
                        // cache stores zero for hits, so we don't
                        // surface it to the caller here.
                        let _ = suppressed;
                    }
                    let mut file_stats = ScanStats::default();
                    let bytes_len = source.len() as u64;
                    let lines = bytecount_lines(&source) as u64;
                    file_stats.record_file(bytes_len, lines);
                    cached_outcomes.push(ScanOutcome::Cached {
                        findings,
                        cache_key: rel.clone(),
                        source,
                        language,
                        stats: file_stats,
                    });
                }
                _ => {
                    to_scan.push(entry.clone());
                }
            }
        }
    } else {
        to_scan = entries.to_vec();
        for entry in entries {
            scanned_files_for_prune.insert(entry.path.display().to_string());
        }
    }

    // Drop the immutable borrow of `cache` before mutating it inside
    // the parallel scan.
    let scan_outcomes: Vec<ScanOutcome> = to_scan
        .par_iter()
        .map_init(ParsePool::new, |pool, entry| {
            // `catch_unwind` so a panic in one worker (e.g. a tree-sitter
            // bug or a bug in a detector) does not bubble up and exit the
            // process with code 101. We surface it as a ScanError instead
            // so the run completes and the user can see which file failed.
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                scan_entry(registry, ctx, entry, pool, project_root, module_prefix)
            }));
            match unwind {
                Ok(res) => match res {
                    Ok((
                        findings,
                        cache_key,
                        source,
                        suppressed_count,
                        stats,
                        dependencies,
                        timing,
                    )) => ScanOutcome::Ok {
                        findings,
                        cache_key,
                        source,
                        language: entry.language,
                        suppressed_count,
                        stats,
                        dependencies,
                        timing,
                    },
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

    // Merge results, write cache entries for misses.
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut source_cache: HashMap<String, Arc<str>> = HashMap::with_capacity(total);
    let mut suppressed_count = 0;
    let mut stats = ScanStats::default();
    let mut timing = TimingCollector::new(collect_stats);
    let mut rescan_files: Vec<(String, bool)> = Vec::new();

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
                timing: file_timing,
            } => {
                if let Some(cache) = cache.as_deref_mut() {
                    let hash = content_hash(&source);
                    let mtime = mtime_of(&cache_key);
                    // Capture whether this entry already existed
                    // before we overwrite it. A "true" rescan with a
                    // changed content hash triggers cascade
                    // invalidation; a brand-new entry does not
                    // (nothing was depending on the stale state).
                    let prior_hash = cache
                        .manifest()
                        .files
                        .get(&cache_key)
                        .map(|m| m.content_hash.clone());
                    let hash_changed = prior_hash
                        .as_deref()
                        .map(|old| old != hash.as_str())
                        .unwrap_or(false);
                    let entry = CacheEntry {
                        schema_version: crate::engine::cache::CACHE_VERSION,
                        file: cache_key.clone(),
                        content_hash: hash,
                        mtime_secs: mtime.0,
                        mtime_nanos: mtime.1,
                        language: language.as_str().to_string(),
                        findings: f.clone(),
                        dependencies: dependencies.clone(),
                        cached_at: crate::engine::cache::iso8601_now(),
                    };
                    if let Err(e) = cache.put(entry) {
                        tracing::warn!(file = %cache_key, error = %e, "failed to write cache entry");
                    }
                    if hash_changed {
                        rescan_files.push((cache_key.clone(), true));
                    }
                }
                findings.append(&mut f);
                source_cache.insert(cache_key, source);
                suppressed_count += ignored;
                stats.merge(&file_stats);
                timing.merge(&file_timing);
            }
            ScanOutcome::Cached { .. } => {
                // Cached outcomes were drained in the previous loop.
            }
            ScanOutcome::Err(e) => {
                errors.push(e);
                stats.record_errored();
            }
        }
    }

    // Now drain the cached outcomes.
    for outcome in cached_outcomes {
        match outcome {
            ScanOutcome::Cached {
                findings: mut f,
                cache_key,
                source,
                stats: file_stats,
                ..
            } => {
                findings.append(&mut f);
                source_cache.insert(cache_key, source);
                stats.merge(&file_stats);
            }
            ScanOutcome::Err(e) => {
                errors.push(e);
                stats.record_errored();
            }
            _ => {}
        }
    }

    tracing::debug!(
        findings = findings.len(),
        errors = errors.len(),
        total,
        "scan chunk complete"
    );

    stats.cache_hits = cache_hit_count;
    stats.cache_misses = stats.files_scanned.saturating_sub(cache_hit_count);

    Ok((
        findings,
        errors,
        source_cache,
        suppressed_count,
        stats,
        timing,
        rescan_files,
    ))
}

/// Apply the current `ScanContext` to a list of cached findings. Drops
/// findings whose rule is filtered out (e.g. via `--skip`).
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

/// Cheap mtime lookup by relative path. Returns `(0, 0)` when the file
/// is missing — the cache entry will be written but the mtime check
/// will be skipped on the next hit.
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
