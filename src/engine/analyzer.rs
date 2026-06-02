//! Scan orchestrator.

use std::path::Path;

use anyhow::Result;

use crate::core::ScanContext;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;
use crate::engine::result::AnalysisResult;
use crate::engine::{
    SCAN_CHUNK_SIZE,
    walk::{analyze_parsed_unit, collect_entries, scan_entries_parallel},
};
use crate::rules::Finding;

/// Builder for [`Analyzer`].
#[derive(Default)]
pub struct AnalyzerBuilder {
    ctx: ScanContext,
    registry: Option<Registry>,
    lang_filter: LanguageFilter,
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

    pub fn build(self) -> Analyzer {
        Analyzer {
            registry: self.registry.unwrap_or_default(),
            ctx: self.ctx,
            lang_filter: self.lang_filter,
        }
    }
}

/// Language-agnostic static analyzer.
pub struct Analyzer {
    registry: Registry,
    ctx: ScanContext,
    lang_filter: LanguageFilter,
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
        let entries = collect_entries(&self.registry, paths, &self.lang_filter)?;
        let mut findings = Vec::new();
        for chunk in entries.chunks(SCAN_CHUNK_SIZE) {
            findings.extend(scan_entries_parallel(&self.registry, &self.ctx, chunk)?);
        }
        sort_findings(&mut findings);
        Ok(AnalysisResult { findings })
    }

    pub fn analyze_units(&self, units: &[crate::core::ParsedUnit]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for unit in units {
            findings.extend(analyze_parsed_unit(&self.registry, &self.ctx, unit));
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
