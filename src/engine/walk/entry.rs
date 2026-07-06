//! Walk paths and collect supported source files.
//!
//! The [`EntrySource`] trait allows injecting a pre-built entry list for
//! tests, avoiding filesystem I/O.

use std::path::Path;
use std::sync::Arc;

use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::Error;
use crate::core::LanguageId;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;

/// A source file queued for analysis.
#[derive(Debug, Clone)]
pub struct ScanEntry {
    pub path: Arc<Path>,
    pub language: LanguageId,
}

/// Pluggable source of [`ScanEntry`] items. Used by [`Analyzer`] to
/// decouple file discovery from analysis.
///
/// # Seam
///
/// Two adapters exist: [`FilesystemWalker`] (the default, walks real
/// directories) and [`ListEntrySource`] (accepts a pre-built vector,
/// suitable for tests).
pub trait EntrySource: Send + Sync + std::fmt::Debug {
    /// Walk or retrieve the list of files to scan. Returns `(entries,
    /// skipped_count)`.
    fn collect(
        &self,
        registry: &Registry,
        lang_filter: &LanguageFilter,
        path_filters: &PathFilters,
        paths: &[&Path],
    ) -> Result<(Vec<ScanEntry>, usize), Error>;
}

/// Default [`EntrySource`] that walks the filesystem using
/// `ignore::WalkBuilder`.
#[derive(Debug, Default)]
pub struct FilesystemWalker;

impl EntrySource for FilesystemWalker {
    fn collect(
        &self,
        registry: &Registry,
        lang_filter: &LanguageFilter,
        path_filters: &PathFilters,
        paths: &[&Path],
    ) -> Result<(Vec<ScanEntry>, usize), Error> {
        let mut entries = Vec::new();
        let mut skipped = 0usize;

        for path in paths {
            let matcher = RootPathMatcher::new(path, path_filters)?;
            let mut builder = WalkBuilder::new(path);
            builder
                .standard_filters(true)
                .add_custom_ignore_filename(".slopguardignore");
            for entry in builder.build().filter_map(Result::ok) {
                if !entry.file_type().is_some_and(|t| t.is_file()) {
                    continue;
                }
                if !matcher.allows(entry.path()) {
                    skipped += 1;
                    continue;
                }
                let Some(plugin) = registry.plugin_for_path(entry.path()) else {
                    skipped += 1;
                    continue;
                };
                let language = plugin.id();
                if !lang_filter.allows(language) {
                    skipped += 1;
                    continue;
                }
                entries.push(ScanEntry {
                    path: Arc::from(entry.path()),
                    language,
                });
            }
        }

        Ok((entries, skipped))
    }
}

/// [`EntrySource`] that returns a pre-built list. Useful for tests that
/// want to verify pipeline behaviour without walking the filesystem.
#[derive(Debug, Clone)]
pub struct ListEntrySource {
    entries: Vec<ScanEntry>,
    skipped: usize,
}

impl ListEntrySource {
    pub fn new(entries: Vec<ScanEntry>) -> Self {
        Self {
            entries,
            skipped: 0,
        }
    }
}

impl EntrySource for ListEntrySource {
    fn collect(
        &self,
        _registry: &Registry,
        _lang_filter: &LanguageFilter,
        _path_filters: &PathFilters,
        _paths: &[&Path],
    ) -> Result<(Vec<ScanEntry>, usize), Error> {
        Ok((self.entries.clone(), self.skipped))
    }
}

/// Walk paths and collect supported source files (no I/O beyond directory walk).
///
/// Honors `.gitignore`/`.ignore` (via `standard_filters(true)`) **and**
/// `.slopguardignore` if present at any walked root.
///
/// Returns the collected entries and the number of files skipped by
/// ignore/language/path filters.
///
/// # Errors
///
/// Returns [`Error::Walk`] when a walk root path does not exist.
#[must_use = "entry collection failures must be handled"]
pub fn collect_entries(
    registry: &Registry,
    paths: &[impl AsRef<Path>],
    lang_filter: &LanguageFilter,
    path_filters: &PathFilters,
) -> Result<(Vec<ScanEntry>, usize), Error> {
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_ref()).collect();
    FilesystemWalker.collect(registry, lang_filter, path_filters, &refs)
}

#[derive(Debug)]
struct RootPathMatcher {
    include: Option<Gitignore>,
    exclude: Option<Gitignore>,
    exclude_tests: bool,
}

impl RootPathMatcher {
    fn new(root: &Path, filters: &PathFilters) -> Result<Self, Error> {
        let base = if root.is_dir() {
            root
        } else {
            root.parent().unwrap_or_else(|| Path::new("."))
        };

        Ok(Self {
            include: build_globset(base, &filters.include)?,
            exclude: build_globset(base, &filters.exclude)?,
            exclude_tests: filters.exclude_tests,
        })
    }

    fn allows(&self, path: &Path) -> bool {
        if self.exclude_tests {
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.contains("_test") {
                    return false;
                }
            }
        }
        if let Some(include) = &self.include {
            if !include.matched(path, false).is_ignore() {
                return false;
            }
        }
        if let Some(exclude) = &self.exclude {
            if exclude.matched(path, false).is_ignore() {
                return false;
            }
        }
        true
    }
}

fn build_globset(base: &Path, patterns: &[String]) -> Result<Option<Gitignore>, Error> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GitignoreBuilder::new(base);
    for pattern in patterns {
        builder
            .add_line(None, pattern)
            .map_err(|e| Error::Walk(e.to_string()))?;
    }
    builder
        .build()
        .map(Some)
        .map_err(|e| Error::Walk(e.to_string()))
}
