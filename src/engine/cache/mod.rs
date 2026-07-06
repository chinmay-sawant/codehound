//! Cache store: manifest, entries, invalidation, eviction.
//!
//! Storage is delegated to a [`CacheBackend`] adapter so that the
//! lifecycle logic (manifest, invalidation, eviction) is independent
//! of the persistence strategy. Two built-in backends:
//! [`DiskBackend`] (default, filesystem) and [`InMemoryBackend`]
//! (tests, ephemeral).

mod backend;
mod disk;
mod hash;
mod memory;
mod session;
mod store_flush;
mod store_lifecycle;
mod store_open;
mod tests;
mod types;

use std::path::PathBuf;

pub use backend::CacheBackend;
pub(crate) use disk::DiskBackend;
pub use hash::{cache_key_for_path, content_hash};
pub use memory::InMemoryBackend;
pub use session::CacheSession;
pub use types::{CacheEntry, CacheError, CacheLookup, CacheManifest, DEFAULT_CACHE_DIR};

/// Cache: entry storage, manifest, invalidation, eviction.
///
/// Default constructors use a [`DiskBackend`]. [`CacheStore::in_memory`]
/// creates a purely in-memory instance suitable for tests.
pub struct CacheStore {
    pub(super) cache_dir: PathBuf,
    pub(super) files_dir: PathBuf,
    pub(super) manifest: CacheManifest,
    pub(super) dirty: bool,
    /// Maximum total size of `files/` in bytes. `0` disables the limit.
    pub(super) max_size_bytes: u64,
    /// Fraction of `max_size_bytes` to retain after eviction.
    pub(super) evict_target_ratio: f64,
    /// Maximum file size eligible for cache reads/writes. `0` disables the limit.
    pub(super) max_file_size_bytes: u64,
    /// Entry persistence backend (disk, in-memory, etc.).
    pub(super) backend: Box<dyn CacheBackend>,
    /// When `true`, `flush` is a no-op and `Drop` does not flush.
    pub(super) ephemeral: bool,
}
