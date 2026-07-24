//! `CacheStore::flush` and the size-based `evict_to_size` helper.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use fs2::FileExt;

use crate::Error;

use super::CacheStore;
use super::hash::cache_key_for_path;
use super::types::{CacheManifest, MANIFEST_NAME};
use crate::engine::io::write_atomic;

const MANIFEST_LOCK_NAME: &str = ".manifest.lock";
const MANIFEST_LOCK_ATTEMPTS: usize = 50;
const ADVISORY_LOCK_MARKER: &[u8] = b"codehound-manifest-advisory-lock-v1\n";

struct ManifestLock {
    file: Option<fs::File>,
}

impl ManifestLock {
    fn acquire(cache_dir: &Path) -> Result<Option<Self>, Error> {
        let path = cache_dir.join(MANIFEST_LOCK_NAME);
        for _ in 0..MANIFEST_LOCK_ATTEMPTS {
            match fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    file.try_lock_exclusive()?;
                    if let Err(error) = file
                        .write_all(ADVISORY_LOCK_MARKER)
                        .and_then(|()| file.sync_all())
                    {
                        let _ = FileExt::unlock(&file);
                        drop(file);
                        let _ = fs::remove_file(&path);
                        return Err(error.into());
                    }
                    return Ok(Some(Self { file: Some(file) }));
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                    if let Some(lock) = Self::recover_advisory_lock(&path)? {
                        return Ok(Some(lock));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.into()),
            }
        }
        tracing::warn!(path = %path.display(), "cache manifest is actively or legacy-locked; skipping this persistence attempt");
        Ok(None)
    }

    fn recover_advisory_lock(path: &Path) -> Result<Option<Self>, Error> {
        let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
        let mut marker = Vec::new();
        file.read_to_end(&mut marker)?;
        if marker != ADVISORY_LOCK_MARKER {
            // ponytail: a pre-advisory CodeHound binary used this pathname as
            // a create_new sentinel. Its contents do not prove the owner is
            // dead, so preserve its lock rather than racing a mixed-version
            // flush. New marked locks are recovered by the kernel lock.
            return Ok(None);
        }
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Some(Self { file: Some(file) })),
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}

impl Drop for ManifestLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = FileExt::unlock(&file);
            // Keep the marked pathname after unlock. Removing it creates an
            // unlink window where another process can lock the old inode while
            // a third process creates and locks a new pathname. The advisory
            // lock itself is released on close/process exit; the small marker
            // file is the stable cross-process rendezvous point.
            drop(file);
        }
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
            || on_disk.rule_config_hash != self.manifest.rule_config_hash
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_cache_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("codehound-{label}-{unique}"))
    }

    #[test]
    fn stale_advisory_lock_file_does_not_block_manifest_persistence() {
        let cache_dir = unique_cache_dir("orphaned-manifest-lock");
        let mut store =
            CacheStore::open_with_capacity(cache_dir.clone(), 1).expect("open disk-backed cache");
        fs::write(cache_dir.join(MANIFEST_LOCK_NAME), ADVISORY_LOCK_MARKER)
            .expect("seed orphaned advisory lock path");
        store.dirty = true;

        store
            .flush()
            .expect("orphaned advisory lock must not block flush");

        assert!(cache_dir.join(MANIFEST_NAME).is_file());
        fs::remove_dir_all(cache_dir).expect("remove test cache");
    }

    #[test]
    fn active_manifest_lock_is_not_stolen() {
        let cache_dir = unique_cache_dir("active-manifest-lock");
        fs::create_dir_all(&cache_dir).expect("create cache dir");
        let path = cache_dir.join(MANIFEST_LOCK_NAME);
        let held = ManifestLock::acquire(&cache_dir)
            .expect("acquire manifest lock")
            .expect("manifest lock should be available");

        assert!(
            ManifestLock::acquire(&cache_dir)
                .expect("lock contention is not an error")
                .is_none(),
            "an active owner must retain the lock"
        );
        assert!(
            path.is_file(),
            "the lock path remains available for its owner"
        );

        drop(held);
        fs::remove_dir_all(cache_dir).expect("remove test cache");
    }
}
