//! `CacheStore` lifecycle: `put`, `remove`, `prune`, `clean_orphans`,
//! `invalidate_file`, `invalidate_dependent`.

use crate::Error;
use crate::rules::Finding;

use super::CacheStore;
use super::hash::cache_key_for_path;
use super::types::{CACHE_VERSION, CacheEntry, FileCacheMeta};

impl CacheStore {
    /// Insert or replace a cache entry. Updates the manifest and marks
    /// the store dirty so [`flush`](Self::flush) writes to disk.
    pub fn put(
        &mut self,
        file: &str,
        content_hash: &str,
        dependencies: &[String],
        findings: Vec<Finding>,
        cached_at: &str,
    ) -> Result<(), Error> {
        let cache_key = cache_key_for_path(file);
        let entry = CacheEntry {
            schema_version: CACHE_VERSION,
            file: file.to_string(),
            findings,
            cached_at: cached_at.to_string(),
        };
        self.backend.store_entry(&cache_key, &entry).map_err(Error::from)?;
        let meta = FileCacheMeta {
            content_hash: content_hash.to_string(),
            dependencies: dependencies.to_vec(),
            cached_at: cached_at.to_string(),
        };
        self.manifest.files.insert(file.to_string(), meta);
        self.dirty = true;
        Ok(())
    }

    /// Remove a single entry from the manifest and from disk. No-op
    /// when `file` is not tracked.
    pub fn remove(&mut self, file: &str) -> Result<(), Error> {
        if self.manifest.files.remove(file).is_some() {
            let cache_key = cache_key_for_path(file);
            self.backend
                .delete_entry(&cache_key)
                .map_err(Error::from)?;
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
        if self.manifest.files.remove(file).is_some() {
            let cache_key = cache_key_for_path(file);
            if let Err(e) = self.backend.delete_entry(&cache_key) {
                tracing::warn!(
                    file,
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
    /// Both the manifest keys and the stored dependency lists use
    /// absolute paths (the canonical form), so matching is a
    /// straightforward string equality check.
    pub fn invalidate_dependent(&mut self, changed_file: &str) -> usize {
        let changed_norm = changed_file.replace('\\', "/");
        let dependents: Vec<String> = self
            .manifest
            .files
            .iter()
            .filter(|(_, m)| {
                m.dependencies
                    .iter()
                    .any(|d| d.replace('\\', "/") == changed_norm)
            })
            .map(|(k, _)| k.clone())
            .collect();
        let count = dependents.len();
        for d in dependents {
            self.invalidate_file(&d);
        }
        count
    }
}
