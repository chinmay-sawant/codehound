//! Disk-backed cache store: manifest, entries, invalidation, eviction.

mod hash;
mod io;
mod store_flush;
mod store_lifecycle;
mod store_open;
mod tests;
mod types;

use std::path::PathBuf;

pub use hash::{cache_key_for_path, content_hash};
pub use types::{
    CACHE_VERSION, CacheEntry, CacheError, CacheLookup, CacheManifest, CacheMetadata,
    DEFAULT_CACHE_DIR, FileCacheMeta,
};

/// Disk-backed cache store. Constructed via [`CacheStore::open`] and
/// used through a single scan run.
pub struct CacheStore {
    pub(super) cache_dir: PathBuf,
    pub(super) files_dir: PathBuf,
    pub(super) manifest: CacheManifest,
    pub(super) dirty: bool,
    /// Maximum total size of `files/` in bytes. `0` disables the limit.
    pub(super) max_size_bytes: u64,
}
