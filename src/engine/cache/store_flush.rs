//! `CacheStore::flush` and the size-based `evict_to_size` helper.

use std::fs;

use crate::Error;

use super::CacheStore;
use super::hash::{iso8601_from_mtime, iso8601_utc_now};
use super::io::write_atomic;
use super::types::{CacheMetadata, MANIFEST_NAME, METADATA_NAME};

impl CacheStore {
    /// Write the manifest and metadata to disk. No-op when no
    /// mutations have happened since the last flush. Should be called
    /// once per scan run, after all `put`/`remove` calls.
    pub fn flush(&mut self) -> Result<(), Error> {
        if !self.dirty {
            return Ok(());
        }
        let manifest_path = self.cache_dir.join(MANIFEST_NAME);
        write_atomic(&manifest_path, &self.manifest)?;
        let metadata = CacheMetadata {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            last_scan: iso8601_utc_now(),
            entry_count: self.manifest.files.len(),
        };
        let metadata_path = self.cache_dir.join(METADATA_NAME);
        write_atomic(&metadata_path, &metadata)?;
        self.dirty = false;

        if self.max_size_bytes > 0 {
            self.evict_to_size()?;
        }
        Ok(())
    }

    /// Remove the oldest cache entries until the total on-disk size is
    /// below `max_size_bytes`. The target is 90% of the limit to avoid
    /// repeated eviction on every small write.
    pub(super) fn evict_to_size(&mut self) -> Result<(), Error> {
        let target = (self.max_size_bytes * 9) / 10;
        let mut current = self.total_size();
        if current <= target {
            return Ok(());
        }

        // Collect entries with their cached_at timestamp and on-disk size.
        let mut entries: Vec<(String, String, u64)> = Vec::new();
        for (file, meta) in &self.manifest.files {
            let path = self.files_dir.join(format!("{}.json", meta.cache_key));
            let size = if let Ok(m) = fs::metadata(&path) {
                m.len()
            } else {
                0
            };
            if size == 0 {
                continue;
            }
            // Read cached_at from the entry file; fall back to manifest mtime.
            let cached_at = self
                .read_entry(&meta.cache_key)
                .map(|e| e.cached_at)
                .unwrap_or_else(|| iso8601_from_mtime(meta.mtime_secs));
            entries.push((file.clone(), cached_at, size));
        }

        // Sort oldest first. ISO8601 UTC timestamps sort lexicographically.
        entries.sort_by(|a, b| a.1.cmp(&b.1));

        for (file, _, size) in entries {
            if current <= target {
                break;
            }
            self.remove(&file)?;
            current = current.saturating_sub(size);
        }

        // Re-write the manifest if we evicted anything.
        if self.dirty {
            let manifest_path = self.cache_dir.join(MANIFEST_NAME);
            write_atomic(&manifest_path, &self.manifest)?;
            let metadata = CacheMetadata {
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                last_scan: iso8601_utc_now(),
                entry_count: self.manifest.files.len(),
            };
            let metadata_path = self.cache_dir.join(METADATA_NAME);
            write_atomic(&metadata_path, &metadata)?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Sum the sizes of all `files/<key>.json` entries in bytes.
    /// Useful for capacity checks and `--diagnostics`.
    pub fn total_size(&self) -> u64 {
        if !self.files_dir.is_dir() {
            return 0;
        }
        let mut total = 0u64;
        if let Ok(entries) = std::fs::read_dir(&self.files_dir) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|t| t.is_file()) {
                    if let Ok(meta) = entry.metadata() {
                        total += meta.len();
                    }
                }
            }
        }
        total
    }
}

impl Drop for CacheStore {
    fn drop(&mut self) {
        if self.dirty {
            // Best-effort: a `Drop` cannot propagate errors, but we
            // can try to flush so an interrupted scan leaves a
            // consistent cache on disk.
            if let Err(e) = self.flush() {
                tracing::warn!(error = %e, "cache flush on drop failed");
            }
        }
    }
}
