//! [`CacheBackend`] trait and its adapters: [`DiskBackend`] and
//! [`InMemoryBackend`].

use std::collections::HashSet;

use super::types::{CacheEntry, CacheError};

/// Storage backend for cache entries. [`CacheStore`](super::CacheStore)
/// delegates entry persistence to this trait so that different storage
/// strategies (disk, in-memory, remote) can be swapped without changing
/// the cache lifecycle logic.
pub(crate) trait CacheBackend: Send + Sync + std::fmt::Debug {
    /// Read a previously stored entry. Returns `None` when the entry
    /// does not exist or is corrupt.
    fn load_entry(&self, cache_key: &str) -> Option<CacheEntry>;

    /// Persist an entry. Replaces any existing entry with the same key.
    fn store_entry(&mut self, cache_key: &str, entry: &CacheEntry) -> Result<(), CacheError>;

    /// Remove a single entry. No-op when the key does not exist.
    fn delete_entry(&mut self, cache_key: &str) -> Result<(), CacheError>;

    /// Approximate total size of all stored entries in bytes.
    fn total_size(&self) -> u64;

    /// Remove on-disk (or in-memory) entries whose keys are not in
    /// `active_keys`. Returns the number of entries removed.
    fn clean_orphans(&self, active_keys: &HashSet<&str>) -> Result<usize, CacheError>;
}
