//! Collect source paths and scan files (parallel parse + detect).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::core::{LanguageId, ParsedUnit, ScanContext};
use crate::engine::language_filter::LanguageFilter;
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;
use crate::engine::result::{ScanError, ScanErrorKind};
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
        let mut builder = WalkBuilder::new(path);
        builder
            .standard_filters(true)
            .add_custom_ignore_filename(".slopguardignore");
        for entry in builder.build().filter_map(Result::ok) {
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
) -> std::result::Result<Vec<Finding>, ScanError> {
    let plugin = match registry.plugin_for_id(entry.language) {
        Some(p) => p,
        None => {
            return Err(ScanError {
                path: entry.path.clone(),
                kind: ScanErrorKind::Engine,
                message: format!("no plugin registered for {:?}", entry.language),
            });
        }
    };

    let bytes = match std::fs::read(&entry.path) {
        Ok(b) => b,
        Err(e) => {
            return Err(ScanError {
                path: entry.path.clone(),
                kind: ScanErrorKind::Io,
                message: format!("reading {}: {e}", entry.path.display()),
            });
        }
    };

    let source = match String::from_utf8(bytes) {
        Ok(s) => Arc::from(s),
        Err(e) => {
            return Err(ScanError {
                path: entry.path.clone(),
                kind: ScanErrorKind::Encoding,
                message: format!("source is not valid UTF-8: {e}"),
            });
        }
    };

    let parser = pool.parser_for(plugin);
    let unit = match plugin.parse_with(parser, &entry.path, source) {
        Ok(u) => u,
        Err(e) => {
            return Err(ScanError {
                path: entry.path.clone(),
                kind: ScanErrorKind::Parse,
                message: format!("parsing {}: {e:#}", entry.path.display()),
            });
        }
    };

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

/// Per-file outcome from a parallel scan: either findings or a structured error.
#[derive(Debug)]
pub enum ScanOutcome {
    Ok(Vec<Finding>),
    Err(ScanError),
}

/// Parallel scan: read → parse → detect → drop per file.
///
/// Per-file errors are collected and returned alongside findings — the scan
/// does **not** abort on the first bad file. Fatal configuration errors
/// (e.g. no plugin for a language) still bubble up as `Err` from this
/// function only if every single file failed.
pub fn scan_entries_parallel(
    registry: &Registry,
    ctx: &ScanContext,
    entries: &[ScanEntry],
) -> Result<(Vec<Finding>, Vec<ScanError>)> {
    let total = entries.len();
    let outcomes: Vec<ScanOutcome> = entries
        .par_iter()
        .map_init(ParsePool::new, |pool, entry| {
            scan_entry(registry, ctx, entry, pool)
        })
        .map(|res| match res {
            Ok(findings) => ScanOutcome::Ok(findings),
            Err(e) => ScanOutcome::Err(e),
        })
        .collect();

    let mut findings = Vec::new();
    let mut errors = Vec::new();
    for outcome in outcomes {
        match outcome {
            ScanOutcome::Ok(mut f) => findings.append(&mut f),
            ScanOutcome::Err(e) => errors.push(e),
        }
    }

    tracing::debug!(
        findings = findings.len(),
        errors = errors.len(),
        total,
        "scan chunk complete"
    );

    Ok((findings, errors))
}
