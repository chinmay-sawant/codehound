//! Collect source paths and scan files (parallel parse + detect).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::core::{LanguageId, ParsedUnit, ScanContext};
use crate::engine::language_filter::LanguageFilter;
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::rules::Finding;

/// A source file queued for analysis.
#[derive(Debug, Clone)]
pub struct ScanEntry {
    pub path: PathBuf,
    pub language: LanguageId,
}

/// Walk paths and collect supported source files (no I/O beyond directory walk).
pub fn collect_entries<I, P>(
    registry: &Registry,
    paths: I,
    lang_filter: &LanguageFilter,
) -> Result<Vec<ScanEntry>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut entries = Vec::new();

    for path in paths {
        let path = path.as_ref();
        for entry in WalkBuilder::new(path)
            .standard_filters(true)
            .build()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let Some(plugin) = registry.plugin_for_path(entry.path()) else {
                continue;
            };
            let language = plugin.id();
            if !lang_filter.allows(language) {
                continue;
            }
            entries.push(ScanEntry {
                path: entry.path().to_path_buf(),
                language,
            });
        }
    }

    Ok(entries)
}

/// Read, parse, and analyze a single file. Drops the parse tree before returning.
///
/// `pool` is reused across many files on the same worker thread (see [`scan_entries_parallel`]).
pub fn scan_entry(
    registry: &Registry,
    ctx: &ScanContext,
    entry: &ScanEntry,
    pool: &mut ParsePool,
) -> Result<Vec<Finding>> {
    let plugin = registry
        .plugin_for_id(entry.language)
        .with_context(|| format!("no plugin registered for {:?}", entry.language))?;

    let bytes =
        std::fs::read(&entry.path).with_context(|| format!("reading {}", entry.path.display()))?;
    let source = Arc::from(
        String::from_utf8(bytes)
            .with_context(|| format!("source is not valid UTF-8: {}", entry.path.display()))?,
    );

    let parser = pool.parser_for(plugin);
    let unit = plugin
        .parse_with(parser, &entry.path, source)
        .with_context(|| format!("parsing {}", entry.path.display()))?;

    Ok(analyze_parsed_unit(registry, ctx, &unit))
}

/// Run enabled detectors on an already-parsed unit.
pub fn analyze_parsed_unit(
    registry: &Registry,
    ctx: &ScanContext,
    unit: &ParsedUnit,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for &idx in registry.detector_indices(unit.language) {
        let det = registry.detector(idx);
        if !det.rule_ids().iter().any(|id| ctx.allows(id)) {
            continue;
        }
        det.run(ctx, unit, &mut findings);
    }
    findings
}

/// Parallel scan: read → parse → detect → drop per file.
///
/// Each Rayon worker keeps one [`ParsePool`] and reuses parsers across files.
pub fn scan_entries_parallel(
    registry: &Registry,
    ctx: &ScanContext,
    entries: &[ScanEntry],
) -> Result<Vec<Finding>> {
    entries
        .par_iter()
        .map_init(ParsePool::new, |pool, entry| {
            scan_entry(registry, ctx, entry, pool)
        })
        .collect::<Result<Vec<_>>>()
        .map(|chunks| chunks.into_iter().flatten().collect())
}
