//! Filesystem-backed [`CacheBackend`].

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use super::backend::CacheBackend;
use super::io::write_atomic;
use super::types::{CACHE_VERSION, CacheEntry, CacheError};

/// Backend that stores each entry as a separate JSON file under
/// `files_dir/<cache_key>.json`.
#[derive(Debug)]
pub struct DiskBackend {
    pub(super) files_dir: PathBuf,
}

impl CacheBackend for DiskBackend {
    fn load_entry(&self, cache_key: &str) -> Option<CacheEntry> {
        let path = self.files_dir.join(format!("{cache_key}.json"));
        if !path.is_file() {
            tracing::warn!(cache_key, "cache entry file missing on disk");
            return None;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read cache entry");
                return None;
            }
        };
        match serde_json::from_slice::<CacheEntry>(&bytes) {
            Ok(e) => {
                if e.schema_version != CACHE_VERSION {
                    tracing::warn!(
                        cache_key,
                        found = e.schema_version,
                        expected = CACHE_VERSION,
                        "cache entry schema mismatch; treating as miss"
                    );
                    return None;
                }
                Some(e)
            }
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "corrupt cache entry; treating as miss"
                );
                None
            }
        }
    }

    fn store_entry(&mut self, cache_key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        let path = self.files_dir.join(format!("{cache_key}.json"));
        write_atomic(&path, entry).map_err(|e| {
            CacheError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })
    }

    fn delete_entry(&mut self, cache_key: &str) -> Result<(), CacheError> {
        let path = self.files_dir.join(format!("{cache_key}.json"));
        if path.is_file() {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    fn total_size(&self) -> u64 {
        if !self.files_dir.is_dir() {
            return 0;
        }
        let mut total = 0u64;
        if let Ok(entries) = fs::read_dir(&self.files_dir) {
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

    fn clean_orphans(&self, active_keys: &HashSet<&str>) -> Result<usize, CacheError> {
        if !self.files_dir.is_dir() {
            return Ok(0);
        }
        let mut removed = 0;
        for entry in fs::read_dir(&self.files_dir)? {
            let entry = entry?;
            let fname = entry.file_name();
            let name = fname.to_string_lossy();
            let Some(key) = name.strip_suffix(".json") else {
                continue;
            };
            if active_keys.contains(key) {
                continue;
            }
            if entry.file_type().is_ok_and(|t| t.is_file()) {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}
