//! Walk paths and collect supported source files.

use std::path::{Path, PathBuf};

use anyhow::Result;
use ignore::WalkBuilder;
use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::core::LanguageId;
use crate::engine::config::PathFilters;
use crate::engine::language_filter::LanguageFilter;
use crate::engine::registry::Registry;

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
///
/// Returns the collected entries and the number of files skipped by
/// ignore/language/path filters.
pub fn collect_entries<I, P>(
    registry: &Registry,
    paths: I,
    lang_filter: &LanguageFilter,
    path_filters: &PathFilters,
) -> Result<(Vec<ScanEntry>, usize)>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut entries = Vec::new();
    let mut skipped = 0usize;

    for path in paths {
        let path = path.as_ref();
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
                path: entry.path().to_path_buf(),
                language,
            });
        }
    }

    Ok((entries, skipped))
}

#[derive(Debug)]
struct RootPathMatcher {
    include: Option<Gitignore>,
    exclude: Option<Gitignore>,
    exclude_tests: bool,
}

impl RootPathMatcher {
    fn new(root: &Path, filters: &PathFilters) -> Result<Self> {
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

fn build_globset(base: &Path, patterns: &[String]) -> Result<Option<Gitignore>> {
    if patterns.is_empty() {
        return Ok(None);
    }

    let mut builder = GitignoreBuilder::new(base);
    for pattern in patterns {
        builder
            .add_line(None, pattern)
            .map_err(anyhow::Error::from)?;
    }
    Ok(Some(builder.build()?))
}
