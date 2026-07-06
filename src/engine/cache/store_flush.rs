//! `CacheStore::flush` and the size-based `evict_to_size` helper.

use std::fs;

use crate::Error;

use super::CacheStore;
use super::io::write_atomic;
use super::types::MANIFEST_NAME;
use crate::engine::time::iso8601_from_secs;

impl CacheStore {
    /// Write the manifest to disk. No-op when no mutations have happened
    /// since the last flush. Should be called once per scan run, after
    /// all `put`/`remove` calls.
    pub fn flush(&mut self) -> Result<(), Error> {
        if !self.dirty {
            return Ok(());
        }
        if self.ephemeral {
            self.dirty = false;
            return Ok(());
        }
        if self.max_size_bytes > 0 {
            self.evict_to_size()?;
        }
        let manifest_path = self.cache_dir.join(MANIFEST_NAME);
        write_atomic(&manifest_path, &self.manifest)?;
        self.dirty = false;
        Ok(())
    }

    /// Remove the oldest cache entries until the total on-disk size is
    /// below `max_size_bytes`. The target ratio is configurable to avoid
    /// repeated eviction on every small write.
    pub(super) fn evict_to_size(&mut self) -> Result<(), Error> {
        let target = ((self.max_size_bytes as f64) * self.evict_target_ratio).floor() as u64;
        let mut current = self.backend.total_size();
        if current <= target {
            return Ok(());
        }

        // Collect entries with their cached_at timestamp and on-disk size.
        let mut entries: Vec<(String, String, u64)> = Vec::new();
        let start_size = current;
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
                .backend
                .load_entry(&meta.cache_key)
                .map(|e| e.cached_at)
                .unwrap_or_else(|| iso8601_from_secs(meta.mtime_secs));
            entries.push((file.clone(), cached_at, size));
        }

        // Sort oldest first. ISO8601 UTC timestamps sort lexicographically.
        entries.sort_by(|a, b| a.1.cmp(&b.1));

        let mut entries_evicted = 0usize;
        for (file, _, size) in entries {
            if current <= target {
                break;
            }
            self.remove(&file)?;
            current = current.saturating_sub(size);
            entries_evicted += 1;
        }

        if entries_evicted > 0 {
            tracing::info!(
                entries_evicted,
                bytes_freed = start_size.saturating_sub(current),
                current_size_mb = current as f64 / (1024.0 * 1024.0),
                target_size_mb = target as f64 / (1024.0 * 1024.0),
                "evicted cache entries to stay under size limit"
            );
        }

        // Mark dirty so flush() writes the updated manifest.
        Ok(())
    }

    /// Sum the sizes of all `files/<key>.json` entries in bytes.
    /// Useful for capacity checks and `--diagnostics`.
    #[cfg(test)]
    pub fn total_size(&self) -> u64 {
        self.backend.total_size()
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