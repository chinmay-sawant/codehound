//! `CacheStore` lifecycle: `put`, `remove`, `prune`, `clean_orphans`,
//! `invalidate_file`, `invalidate_dependent`.

use crate::Error;
use crate::engine::path_identity::{normalize_project_path, project_paths_eq};
use crate::rules::Finding;

use super::CacheStore;
use super::hash::cache_key_for_path;
use super::types::{CACHE_VERSION, FileCacheMeta};

impl CacheStore {
    /// Insert or replace a cache entry. Updates the manifest and marks
    /// the store dirty so [`flush`](Self::flush) writes to disk.
    ///
    /// Manifest keys and dependency paths are stored in
    /// [`normalize_project_path`] form.
    pub fn put(
        &mut self,
        file: &str,
        content_hash: &str,
        dependencies: &[String],
        findings: Vec<Finding>,
        cached_at: &str,
    ) -> Result<(), Error> {
        self.put_with_suppressed_count(file, content_hash, dependencies, findings, 0, cached_at)
    }

    /// Insert or replace a cache entry with source-ignore accounting.
    pub fn put_with_suppressed_count(
        &mut self,
        file: &str,
        content_hash: &str,
        dependencies: &[String],
        findings: Vec<Finding>,
        suppressed_count: usize,
        cached_at: &str,
    ) -> Result<(), Error> {
        self.put_with_suppressed_count_borrowed(
            file,
            content_hash,
            dependencies,
            &findings,
            suppressed_count,
            cached_at,
        )
    }

    /// Insert or replace a cache entry while borrowing findings from the
    /// current scan result.
    pub fn put_with_suppressed_count_borrowed(
        &mut self,
        file: &str,
        content_hash: &str,
        dependencies: &[String],
        findings: &[Finding],
        suppressed_count: usize,
        cached_at: &str,
    ) -> Result<(), Error> {
        let file = normalize_project_path(file);
        let deps: Vec<String> = dependencies
            .iter()
            .map(|d| normalize_project_path(d))
            .collect();
        let cache_key = cache_key_for_path(&file);
        self.backend
            .store_entry_borrowed(
                &cache_key,
                CACHE_VERSION,
                &file,
                findings,
                suppressed_count,
                cached_at,
            )
            .map_err(Error::from)?;
        let meta = FileCacheMeta {
            content_hash: content_hash.to_string(),
            dependencies: deps,
            cached_at: cached_at.to_string(),
        };
        self.manifest.files.insert(file, meta);
        self.dirty = true;
        Ok(())
    }

    /// Remove a single entry from the manifest and from disk. No-op
    /// when `file` is not tracked.
    pub fn remove(&mut self, file: &str) -> Result<(), Error> {
        if self.manifest.files.remove(file).is_some() {
            let cache_key = cache_key_for_path(file);
            self.backend.delete_entry(&cache_key).map_err(Error::from)?;
            self.dirty = true;
        }
        Ok(())
    }

    /// Drop every entry not present in `scanned_files` from the
    /// manifest and from disk. Use after a scan completes to remove
    /// entries for files that no longer exist.
    pub fn prune(
        &mut self,
        scanned_files: &std::collections::HashSet<String>,
    ) -> Result<usize, Error> {
        let to_remove: Vec<String> = self
            .manifest
            .files
            .keys()
            .filter(|k| !scanned_files.contains(*k))
            .cloned()
            .collect();
        let count = to_remove.len();
        for file in to_remove {
            self.remove(&file)?;
        }
        Ok(count)
    }

    /// Remove on-disk `files/<key>.json` entries whose keys are not
    /// present in the manifest. These orphans appear when the
    /// manifest is torn (e.g. concurrent writes). Returns the number
    /// of files removed.
    pub fn clean_orphans(&self) -> Result<usize, Error> {
        let active_keys: std::collections::HashSet<String> = self
            .manifest
            .files
            .keys()
            .map(|file| cache_key_for_path(file))
            .collect();
        let active_refs: std::collections::HashSet<&str> =
            active_keys.iter().map(String::as_str).collect();
        self.backend
            .clean_orphans(&active_refs)
            .map_err(Error::from)
    }

    /// Invalidate the entry for `file`, removing it from the manifest
    /// and deleting the on-disk entry.
    pub fn invalidate_file(&mut self, file: &str) {
        let file = normalize_project_path(file);
        if self.manifest.files.remove(&file).is_some() {
            let cache_key = cache_key_for_path(&file);
            if let Err(e) = self.backend.delete_entry(&cache_key) {
                tracing::warn!(
                    file = %file,
                    cache_key = %cache_key,
                    error = %e,
                    "failed to delete invalidated cache entry"
                );
            }
            self.dirty = true;
        }
    }

    /// Invalidate every entry whose `dependencies` list contains
    /// `changed_file`. Returns the number of entries invalidated.
    ///
    /// Matching uses [`project_paths_eq`] so `\` vs `/` and `./` do not
    /// miss cascade edges.
    pub fn invalidate_dependent(&mut self, changed_file: &str) -> usize {
        let changed_norm = normalize_project_path(changed_file);
        let dependents: Vec<String> = self
            .manifest
            .files
            .iter()
            .filter(|(_, m)| {
                m.dependencies
                    .iter()
                    .any(|d| project_paths_eq(d, &changed_norm))
            })
            .map(|(k, _)| k.clone())
            .collect();
        let count = dependents.len();
        for d in dependents {
            self.invalidate_file(&d);
        }
        count
    }

    /// Expand a dirty set through reverse dependency edges in the
    /// manifest until fixpoint (same-scan cascade).
    ///
    /// If `A` depends on `B` and `B` is dirty, `A` becomes dirty so it
    /// is re-parsed in **this** scan rather than only on the next run.
    pub fn expand_dirty_fixpoint(&self, dirty: &mut std::collections::HashSet<String>) {
        // Normalize inputs.
        let mut normalized: std::collections::HashSet<String> =
            dirty.iter().map(|p| normalize_project_path(p)).collect();
        loop {
            let mut added = Vec::new();
            for (file, meta) in &self.manifest.files {
                let file_n = normalize_project_path(file);
                if normalized.contains(&file_n) {
                    continue;
                }
                if meta
                    .dependencies
                    .iter()
                    .any(|d| normalized.contains(&normalize_project_path(d)))
                {
                    added.push(file_n);
                }
            }
            if added.is_empty() {
                break;
            }
            normalized.extend(added);
        }
        *dirty = normalized;
    }

    /// Drop all cached entries after a tool-version mismatch (mass stale).
    ///
    /// Keeps the store open with an empty manifest at the current
    /// `CARGO_PKG_VERSION`. On-disk entry files are deleted best-effort.
    pub fn mass_stale_for_tool_version(&mut self) {
        let keys: Vec<String> = self.manifest.files.keys().cloned().collect();
        for file in keys {
            self.invalidate_file(&file);
        }
        self.manifest.tool_version = env!("CARGO_PKG_VERSION").to_string();
        self.dirty = true;
        tracing::warn!(
            version = env!("CARGO_PKG_VERSION"),
            "cache mass-staled after tool_version mismatch; entries will rebuild this scan"
        );
    }
}
