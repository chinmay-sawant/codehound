//! Cache data types and on-disk schema constants.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::rules::Finding;

/// Cache file format version. Bump on any breaking change to the JSON
/// shapes persisted on disk. Older caches are refused on `open()`.
pub const CACHE_VERSION: u32 = 2;

/// Conventional cache directory name. Used when no override is supplied.
pub const DEFAULT_CACHE_DIR: &str = ".codehound-cache";

pub(super) const MANIFEST_NAME: &str = "manifest.json";
pub(super) const FILES_SUBDIR: &str = "files";

/// Cache manifest: cheap O(1) lookup for per-file state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheManifest {
    pub schema_version: u32,
    pub tool_version: String,
    pub files: HashMap<String, FileCacheMeta>,
}

/// Per-file metadata stored in the manifest. Mirrors the on-disk entry
/// minus the findings list, so the manifest stays small even for large
/// projects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCacheMeta {
    /// `sha256:<hex>` of the file's source text at scan time.
    pub content_hash: String,
    /// Relative file paths this file imports (for transitive
    /// invalidation). Empty when dependency tracking is not enabled.
    #[serde(default)]
    pub dependencies: Vec<String>,
    /// ISO-8601 UTC timestamp when the entry was last written.
    pub cached_at: String,
}

/// Full per-file cache entry. Persisted at
/// `<cache_dir>/files/<cache_key>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub schema_version: u32,
    pub file: String,
    pub findings: Vec<Finding>,
    pub cached_at: String,
}

/// Outcome of a cache lookup.
#[derive(Debug, Clone)]
pub enum CacheLookup {
    /// Fresh entry; findings are returned.
    Hit(CacheEntry),
    /// File is in the manifest but stale (content hash mismatch or missing/corrupt entry).
    Stale,
    /// File has no entry in the manifest.
    Miss,
}

/// Errors specific to the cache layer. `CacheStore` never panics on a
/// corrupted entry — it returns `None` from [`CacheBackend::load_entry`]
/// and logs the error.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("unsupported cache schema version: {found}, expected {expected}")]
    SchemaMismatch { found: u32, expected: u32 },
}
