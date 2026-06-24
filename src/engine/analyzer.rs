//! Scan orchestrator.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use crate::core::ScanContext;
use crate::engine::cache::CacheStore;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;
use crate::engine::result::AnalysisResult;
use crate::engine::stats::ScanStats;
use crate::engine::timing::TimingCollector;
use crate::engine::{
    SCAN_CHUNK_SIZE,
    walk::{analyze_parsed_unit_with_context, collect_entries, scan_entries_parallel},
};
use crate::rules::Finding;

/// Builder for [`Analyzer`].
#[derive(Default)]
pub struct AnalyzerBuilder {
    ctx: ScanContext,
    registry: Option<Registry>,
    lang_filter: LanguageFilter,
    path_filters: PathFilters,
    collect_stats: bool,
}

impl AnalyzerBuilder {
    pub fn scan_context(mut self, ctx: ScanContext) -> Self {
        self.ctx = ctx;
        self
    }

    pub fn language_filter(mut self, filter: LanguageFilter) -> Self {
        self.lang_filter = filter;
        self
    }

    pub fn path_filters(mut self, filters: PathFilters) -> Self {
        self.path_filters = filters;
        self
    }

    pub fn collect_stats(mut self, collect: bool) -> Self {
        self.collect_stats = collect;
        self
    }

    pub fn build(self) -> Analyzer {
        Analyzer {
            registry: self.registry.unwrap_or_default(),
            ctx: self.ctx,
            lang_filter: self.lang_filter,
            path_filters: self.path_filters,
            collect_stats: self.collect_stats,
        }
    }
}

/// Language-agnostic static analyzer.
pub struct Analyzer {
    registry: Registry,
    ctx: ScanContext,
    lang_filter: LanguageFilter,
    path_filters: PathFilters,
    collect_stats: bool,
}

impl Analyzer {
    pub fn builder() -> AnalyzerBuilder {
        AnalyzerBuilder::default()
    }

    pub fn scan_context(&self) -> &ScanContext {
        &self.ctx
    }

    /// Run the scan. When `cache` is `Some`, the scan consults the
    /// cache for files whose content hash has not changed, and writes
    /// back new entries for files it scans. The cache is flushed
    /// before this method returns.
    pub fn analyze_paths<I, P>(
        &self,
        paths: I,
        mut cache: Option<&mut CacheStore>,
    ) -> Result<AnalysisResult>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut timing = TimingCollector::new(self.collect_stats);

        let (entries, files_skipped) = timing.measure("file_walk", || {
            collect_entries(&self.registry, paths, &self.lang_filter, &self.path_filters)
        })?;

        let mut findings = Vec::new();
        let mut errors = Vec::new();
        let mut source_cache: HashMap<String, Arc<str>> = HashMap::new();
        let mut suppressed_count = 0;
        let mut stats = ScanStats::default();
        stats.files_skipped = files_skipped;
        let mut scanned_files: std::collections::HashSet<String> =
            std::collections::HashSet::with_capacity(entries.len());
        for entry in &entries {
            scanned_files.insert(entry.path.display().to_string());
        }

        for chunk in entries.chunks(SCAN_CHUNK_SIZE) {
            let (
                chunk_findings,
                chunk_errors,
                chunk_source_cache,
                chunk_suppressed_count,
                chunk_stats,
                chunk_timing,
            ) = scan_entries_parallel(&self.registry, &self.ctx, chunk, cache.as_deref_mut())?;
            findings.extend(chunk_findings);
            errors.extend(chunk_errors);
            source_cache.extend(chunk_source_cache);
            suppressed_count += chunk_suppressed_count;
            stats.merge(&chunk_stats);
            timing.merge(&chunk_timing);
        }

        // Prune orphan cache entries (files that were deleted since
        // the last scan). Done at the analyzer level so it still runs
        // when `entries` is empty.
        if let Some(cache) = cache.as_deref_mut() {
            if let Ok(removed) = cache.prune(&scanned_files) {
                if removed > 0 {
                    tracing::debug!(removed, "pruned stale cache entries");
                }
            }
        }

        timing.measure("sort_results", || sort_findings(&mut findings));

        if !errors.is_empty() {
            tracing::warn!(
                error_count = errors.len(),
                "scan completed with per-file errors"
            );
        }

        let mut result = AnalysisResult {
            findings,
            errors,
            source_cache,
            suppressed_count,
            stats: None,
        };

        if self.collect_stats {
            let mut scan_stats = ScanStats::from_result(&result);
            scan_stats.files_scanned = stats.files_scanned;
            scan_stats.files_skipped = stats.files_skipped;
            scan_stats.files_errored = stats.files_errored;
            scan_stats.bytes_scanned = stats.bytes_scanned;
            scan_stats.lines_scanned = stats.lines_scanned;
            scan_stats.rules_executed = stats.rules_executed;
            scan_stats.detectors_loaded = self.registry.detector_count();
            scan_stats.timing = Some(timing.to_summary());
            result.stats = Some(scan_stats);
        }

        if let Some(cache) = cache {
            if let Err(e) = cache.flush() {
                tracing::warn!(error = %e, "failed to flush incremental cache");
            }
        }

        Ok(result)
    }

    pub fn analyze_units(&self, units: &[crate::core::ParsedUnit]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for unit in units {
            findings.extend(analyze_parsed_unit_with_context(
                &self.registry,
                &self.ctx,
                unit,
            ));
        }
        sort_findings(&mut findings);
        findings
    }
}

fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.line.cmp(&b.line))
            .then(a.column.cmp(&b.column))
    });
}
