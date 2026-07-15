//! `Analyzer::analyze_paths`: top-level scan orchestration with cache,
//! cascade-invalidation, pruning, and stats aggregation.

use std::path::Path;
use std::time::Instant;

use crate::Error;
use crate::engine::{
    SCAN_CHUNK_SIZE,
    cache::CacheSession,
    dependencies::{discover_project_root, go_module_prefix},
    result::AnalysisResult,
    stats::ScanStats,
    timing,
    walk::scan_entries_parallel,
};

use super::types::Analyzer;

impl Analyzer {
    /// Run the scan. When `cache` is `Some`, the scan consults the
    /// cache for files whose content hash has not changed, and writes
    /// back new entries for files it scans. Cache failures are best-effort:
    /// they are logged and the scan result remains available.
    ///
    /// # Errors
    ///
    /// Returns an error when file discovery fails (invalid paths, I/O while
    /// walking the tree), or when a configured language plugin fails to parse
    /// a file in a way that aborts the scan (per [`crate::core::FailPolicy`]).
    #[must_use = "scan errors and findings are returned in AnalysisResult"]
    pub fn analyze_paths(
        &self,
        paths: &[impl AsRef<Path>],
        mut cache: Option<CacheSession<'_>>,
    ) -> Result<AnalysisResult, Error> {
        let wall_start = Instant::now();
        let mut timing = timing::TimingCollector::new(self.collect_stats);
        let start = paths
            .first()
            .map(|p| p.as_ref())
            .unwrap_or_else(|| Path::new("."));
        let scan_root = if start.is_file() {
            start.parent().unwrap_or(start).to_path_buf()
        } else {
            start.to_path_buf()
        };
        let project_root = discover_project_root(start);
        let module_prefix = go_module_prefix(&project_root);
        let dependency_root = if module_prefix.is_some() {
            project_root
        } else {
            scan_root
        };

        let (entries, files_skipped) = timing.measure("file_walk", || {
            let path_refs: Vec<&Path> = paths.iter().map(|p| p.as_ref()).collect();
            self.entry_source.collect(
                &self.registry,
                &self.lang_filter,
                &self.path_filters,
                &path_refs,
            )
        })?;

        let mut acc = crate::engine::PipelineAccumulator::new(files_skipped);
        if cache.is_some() {
            for entry in &entries {
                acc.record_scanned(entry.path.display().to_string());
            }
        }

        if let Some(cache) = cache.as_mut() {
            cache.ensure_rule_config_hash(&self.ctx.rule_config_fingerprint());
        }

        let _timing_session = timing::begin_global(self.collect_stats);
        for chunk in entries.chunks(SCAN_CHUNK_SIZE) {
            let chunk = match scan_entries_parallel(
                &self.registry,
                &self.ctx,
                chunk,
                cache.as_mut(),
                &dependency_root,
                module_prefix.as_deref(),
            ) {
                Ok(chunk) => chunk,
                Err(e) => return Err(Error::Walk(e.to_string())),
            };
            let rescan_files = acc.merge_chunk(chunk, &mut timing);

            // Transitive invalidation: every file whose content
            // hash changed is, by definition, a dependency of any
            // cache entry that still lists it. Walk the manifest and
            // drop those dependents so the next scan (or a
            // re-lookup) re-parses them. Brand-new entries (no
            // previous hash) are NOT cascaded — there is nothing to
            // invalidate yet.
            if let Some(cache) = cache.as_mut() {
                for (rescanned_file, hash_changed) in rescan_files {
                    if !hash_changed {
                        continue;
                    }
                    let removed = cache.invalidate_dependent(&rescanned_file);
                    if removed > 0 {
                        tracing::info!(
                            file = %rescanned_file,
                            removed,
                            "cascade-invalidated dependents"
                        );
                    }
                }
            }
        }

        // Prune orphan cache entries (files that were deleted since
        // the last scan). Done at the analyzer level so it still runs
        // when `entries` is empty.
        if let Some(cache) = cache.as_mut() {
            match cache.prune(acc.scanned_files()) {
                Ok(removed) if removed > 0 => {
                    tracing::debug!(removed, "pruned stale cache entries");
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "failed to prune stale cache entries");
                }
            }
        }

        // Project-level analysis: let detectors emit cross-file findings.
        let det_idx = timing.start("detector_finalize");
        for &idx in self.registry.detector_indices_for_project() {
            if let Some(detector) = self.registry.detector(idx) {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    detector.finalize(&self.ctx, acc.findings_mut());
                }));
                if let Err(payload) = result {
                    acc.record_error(crate::engine::ScanError {
                        path: std::path::PathBuf::from("<detector-finalize>"),
                        kind: crate::engine::ScanErrorKind::Engine,
                        message: format!(
                            "detector finalization panicked: {}",
                            panic_message(&payload)
                        ),
                    });
                }
            }
        }
        crate::engine::walk::filter_findings(&self.ctx, acc.findings_mut());
        timing.stop(det_idx);

        timing.measure("sort_results", || {
            acc.findings_mut().sort_by(|a, b| {
                a.file
                    .cmp(&b.file)
                    .then(a.line.cmp(&b.line))
                    .then(a.column.cmp(&b.column))
            });
        });

        if !acc.errors().is_empty() {
            tracing::warn!(
                error_count = acc.errors().len(),
                "scan completed with per-file errors"
            );
        }

        let chunk_stats = acc.take_stats();
        let mut result = AnalysisResult {
            findings: acc.take_findings(),
            errors: acc.take_errors(),
            source_cache: acc.take_source_cache(),
            suppressed_count: acc.suppressed_count(),
            stats: None,
        };
        // Always attach basic counts + wall time so summaries can show ms and
        // cache hit/miss. Phase/detector spans stay behind `collect_stats`.
        let mut scan_stats = chunk_stats;
        scan_stats.merge(&ScanStats::from_findings(&result.findings, 0));
        scan_stats.findings_suppressed = result.suppressed_count;
        scan_stats.detectors_loaded = self.registry.detector_count();
        let wall = wall_start.elapsed();
        let mut summary = if self.collect_stats {
            timing.to_summary()
        } else {
            timing::TimingSummary {
                total_wall_time: wall,
                phases: Vec::new(),
            }
        };
        // Prefer true wall clock over summed phase spans (phases may overlap).
        summary.total_wall_time = wall;
        scan_stats.timing = Some(summary);
        result.stats = Some(scan_stats);

        if let Some(mut cache) = cache {
            if let Err(e) = cache.flush() {
                tracing::warn!(error = %e, "failed to flush incremental cache");
            }
        }

        Ok(result)
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
