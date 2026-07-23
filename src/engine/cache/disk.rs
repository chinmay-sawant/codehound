//! Filesystem-backed [`CacheBackend`].

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use serde::Serialize;

use super::backend::CacheBackend;
use super::types::{CACHE_VERSION, CacheEntry, CacheError};
use crate::engine::io::write_atomic;
use crate::rules::Finding;

#[derive(Serialize)]
struct BorrowedCacheEntry<'a> {
    schema_version: u32,
    file: &'a str,
    findings: &'a [Finding],
    suppressed_count: usize,
    cached_at: &'a str,
}

/// Backend that stores each entry as a separate JSON file under
/// `files_dir/<cache_key>.json`.
#[derive(Debug)]
pub(crate) struct DiskBackend {
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
        write_atomic(&path, entry).map_err(cache_error)
    }

    fn store_entry_borrowed(
        &mut self,
        cache_key: &str,
        schema_version: u32,
        file: &str,
        findings: &[Finding],
        suppressed_count: usize,
        cached_at: &str,
    ) -> Result<(), CacheError> {
        let path = self.files_dir.join(format!("{cache_key}.json"));
        let entry = BorrowedCacheEntry {
            schema_version,
            file,
            findings,
            suppressed_count,
            cached_at,
        };
        write_atomic(&path, &entry).map_err(cache_error)
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
                if entry.file_type().is_ok_and(|t| t.is_file())
                    && let Ok(meta) = entry.metadata()
                {
                    total += meta.len();
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

fn cache_error(error: crate::Error) -> CacheError {
    match error {
        crate::Error::Io(source) => CacheError::Io(source),
        crate::Error::PathIo { path, op, source } => CacheError::PathIo { path, op, source },
        crate::Error::Json(source) => CacheError::Serialization(source),
        other => CacheError::Io(std::io::Error::other(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::cache_error;
    use crate::engine::CacheError;
    use crate::error::IoOp;

    #[test]
    fn cache_error_preserves_path_and_operation() {
        let error = cache_error(crate::Error::path_io(
            "cache/files/entry.json",
            IoOp::Write,
            std::io::Error::other("read-only filesystem"),
        ));

        assert!(matches!(
            error,
            CacheError::PathIo {
                path,
                op: IoOp::Write,
                ..
            } if path == "cache/files/entry.json"
        ));
    }

    #[test]
    fn cache_error_preserves_serialization_failures() {
        let source = serde_json::from_str::<String>("not-json").expect_err("invalid JSON");
        let error = cache_error(crate::Error::Json(source));
        assert!(matches!(error, CacheError::Serialization(_)));
    }
}
