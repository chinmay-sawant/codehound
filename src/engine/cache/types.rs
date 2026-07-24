//! Cache data types and on-disk schema constants.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::IoOp;

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
    /// On-disk schema version for this manifest.
    pub schema_version: u32,
    /// CodeHound version that last wrote the cache.
    pub tool_version: String,
    /// Fingerprint of rule-filter settings (profile/only/skip/taint/bp).
    /// Mismatch mass-stales entries so a narrow pack cannot poison a full run.
    #[serde(default)]
    pub rule_config_hash: String,
    /// Per-file metadata keyed by normalized project-relative path.
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
    /// On-disk schema version for this entry.
    pub schema_version: u32,
    /// Project-relative file path this entry belongs to.
    pub file: String,
    /// Source hash this entry was produced from. Kept in the entry as well as
    /// the manifest so a concurrent replacement cannot become a false hit.
    #[serde(default)]
    pub content_hash: String,
    /// Finding-affecting rule configuration used to produce this entry.
    #[serde(default)]
    pub rule_config_hash: String,
    /// Findings captured for this file at scan time.
    pub findings: Vec<Finding>,
    /// Number of findings removed or marked suppressed by source ignores.
    /// Defaults to zero for entries written before this field existed.
    #[serde(default)]
    pub suppressed_count: usize,
    /// ISO-8601 UTC timestamp when the entry was last written.
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
/// corrupted entry — it returns `None` from
/// [`CacheBackend::load_entry`](crate::engine::CacheBackend::load_entry)
/// and logs the error.
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// A filesystem operation failed without additional path context.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A filesystem operation failed while writing a specific cache path.
    #[error("{op} {path}: {source}")]
    PathIo {
        /// Cache path involved in the operation.
        path: String,
        /// Filesystem operation that failed.
        op: IoOp,
        #[source]
        /// Underlying operating-system error.
        source: std::io::Error,
    },

    /// Cache JSON could not be serialized.
    #[error("serializing cache data: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The cache entry was written by an incompatible schema version.
    #[error("unsupported cache schema version: {found}, expected {expected}")]
    SchemaMismatch {
        /// Version found in the cache.
        found: u32,
        /// Version understood by this binary.
        expected: u32,
    },
}
