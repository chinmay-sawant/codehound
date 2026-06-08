//! Scan orchestrator.

use std::path::Path;

use anyhow::Result;

use crate::core::ScanContext;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;
use crate::engine::result::AnalysisResult;
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

    pub fn build(self) -> Analyzer {
        Analyzer {
            registry: self.registry.unwrap_or_default(),
            ctx: self.ctx,
            lang_filter: self.lang_filter,
            path_filters: self.path_filters,
        }
    }
}

/// Language-agnostic static analyzer.
pub struct Analyzer {
    registry: Registry,
    ctx: ScanContext,
    lang_filter: LanguageFilter,
    path_filters: PathFilters,
}

impl Analyzer {
    pub fn builder() -> AnalyzerBuilder {
        AnalyzerBuilder::default()
    }

    pub fn scan_context(&self) -> &ScanContext {
        &self.ctx
    }

    pub fn analyze_paths<I, P>(&self, paths: I) -> Result<AnalysisResult>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let entries =
            collect_entries(&self.registry, paths, &self.lang_filter, &self.path_filters)?;
        let mut findings = Vec::new();
        let mut errors = Vec::new();
        for chunk in entries.chunks(SCAN_CHUNK_SIZE) {
            let (chunk_findings, chunk_errors) =
                scan_entries_parallel(&self.registry, &self.ctx, chunk)?;
            findings.extend(chunk_findings);
            errors.extend(chunk_errors);
        }
        sort_findings(&mut findings);
        if !errors.is_empty() {
            tracing::warn!(
                error_count = errors.len(),
                "scan completed with per-file errors"
            );
        }
        Ok(AnalysisResult {
            findings,
            errors,
            source_cache: Default::default(),
        })
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
