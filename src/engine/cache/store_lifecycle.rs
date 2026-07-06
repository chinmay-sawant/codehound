//! `CacheStore` lifecycle: `put`, `remove`, `prune`, `clean_orphans`,
//! `invalidate_file`, `invalidate_dependent`, plus the `read_entry` helper
//! that backs `lookup`/`get`.

use crate::Error;

use super::CacheStore;
use super::hash::cache_key_for_path;
use super::types::{CacheEntry, FileCacheMeta};

impl CacheStore {
    /// Insert or replace a cache entry. Updates the manifest and marks
    /// the store dirty so [`flush`](Self::flush) writes to disk.
    pub fn put(&mut self, entry: CacheEntry) -> Result<(), Error> {
        let cache_key = cache_key_for_path(&entry.file);
        self.backend.store_entry(&cache_key, &entry).map_err(|e| {
            Error::Walk(format!("storing cache entry {cache_key}: {e}"))
        })?;
        let meta = FileCacheMeta {
            cache_key,
            content_hash: entry.content_hash.clone(),
            mtime_secs: entry.mtime_secs,
            mtime_nanos: entry.mtime_nanos,
            language: entry.language.clone(),
            dependencies: entry.dependencies.clone(),
        };
        self.manifest.files.insert(entry.file, meta);
        self.dirty = true;
        Ok(())
    }

    /// Remove a single entry from the manifest and from disk. No-op
    /// when `file` is not tracked.
    pub fn remove(&mut self, file: &str) -> Result<(), Error> {
        if let Some(meta) = self.manifest.files.remove(file) {
            self.backend.delete_entry(&meta.cache_key).map_err(|e| {
                Error::Walk(format!("removing cache entry {}: {e}", meta.cache_key))
            })?;
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
        let active_keys: std::collections::HashSet<&str> = self
            .manifest
            .files
            .values()
            .map(|m| m.cache_key.as_str())
            .collect();
        self.backend.clean_orphans(&active_keys).map_err(|e| {
            Error::Walk(format!("cleaning cache orphans: {e}"))
        })
    }

    /// Lazily invalidate the entry for `file`. Equivalent to
    /// [`remove`](Self::remove) but kept as a separate name for use by
    /// callers that invalidate without deleting the on-disk entry
    /// (e.g. when an external observer signals staleness).
    pub fn invalidate_file(&mut self, file: &str) {
        if self.manifest.files.remove(file).is_some() {
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

/// Delegate to the backend to load an entry. The `lookup` and `get`
/// methods call this through `CacheStore::read_entry`.
pub(super) fn read_entry(store: &CacheStore, cache_key: &str) -> Option<CacheEntry> {
    store.backend.load_entry(cache_key)
}
