//! `CacheStore::flush` and the size-based `evict_to_size` helper.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crate::Error;

use super::CacheStore;
use super::hash::cache_key_for_path;
use super::types::{CacheManifest, MANIFEST_NAME};
use crate::engine::io::write_atomic;

const MANIFEST_LOCK_NAME: &str = ".manifest.lock";
const MANIFEST_LOCK_ATTEMPTS: usize = 50;

struct ManifestLock(PathBuf);

impl ManifestLock {
    fn acquire(cache_dir: &Path) -> Result<Option<Self>, Error> {
        let path = cache_dir.join(MANIFEST_LOCK_NAME);
        for _ in 0..MANIFEST_LOCK_ATTEMPTS {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Some(Self(path))),
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        // ponytail: orphaned locks (crashed owner) are intentionally not stolen.
        // Scan stays correct with a cold/in-memory flush skip; upgrade path is
        // lock ownership tokens + stale reclaim after a bounded age.
        tracing::warn!(path = %path.display(), "cache manifest remains locked; skipping persistence without taking ownership of the lock");
        Ok(None)
    }
}

impl Drop for ManifestLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl CacheStore {
    /// Write the manifest to disk. No-op when no mutations have happened
    /// since the last flush. Should be called once per scan run, after
    /// all `put`/`remove` calls.
    ///
    /// # Errors
    ///
    /// Returns [`Error`] when eviction, serialization, or atomic persistence
    /// fails.
    pub fn flush(&mut self) -> Result<(), Error> {
        if !self.dirty {
            return Ok(());
        }
        if self.ephemeral {
            self.dirty = false;
            return Ok(());
        }
        let Some(_lock) = ManifestLock::acquire(&self.cache_dir)? else {
            return Ok(());
        };
        self.merge_concurrent_manifest()?;
        if self.max_size_bytes > 0 {
            self.evict_to_size()?;
        }
        let manifest_path = self.cache_dir.join(MANIFEST_NAME);
        write_atomic(&manifest_path, &self.manifest)?;
        self.dirty = false;
        self.removed_files.clear();
        Ok(())
    }

    fn merge_concurrent_manifest(&mut self) -> Result<(), Error> {
        let manifest_path = self.cache_dir.join(MANIFEST_NAME);
        if !manifest_path.is_file() {
            return Ok(());
        }
        let on_disk: CacheManifest = match serde_json::from_slice(&fs::read(&manifest_path)?) {
            Ok(manifest) => manifest,
            Err(error) => {
                tracing::warn!(path = %manifest_path.display(), error = %error, "manifest changed concurrently but is unreadable; retaining local manifest");
                return Ok(());
            }
        };
        if on_disk.schema_version != self.manifest.schema_version
            || on_disk.tool_version != self.manifest.tool_version
        {
            return Ok(());
        }
        for (file, meta) in on_disk.files {
            if !self.manifest.files.contains_key(&file) && !self.removed_files.contains(&file) {
                self.manifest.files.insert(file, meta);
            }
        }
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
            let path = self
                .files_dir
                .join(format!("{}.json", cache_key_for_path(file)));
            let size = if let Ok(m) = fs::metadata(&path) {
                m.len()
            } else {
                0
            };
            if size == 0 {
                continue;
            }
            entries.push((file.clone(), meta.cached_at.clone(), size));
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
