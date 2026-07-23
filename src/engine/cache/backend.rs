//! [`CacheBackend`] trait and its adapters: [`DiskBackend`] and
//! [`InMemoryBackend`].

use std::collections::HashSet;

use crate::rules::Finding;

use super::types::{CacheEntry, CacheError};

/// Immutable identity metadata for a borrowed cache entry write.
#[derive(Debug, Clone, Copy)]
pub struct CacheEntryIdentity<'a> {
    /// Project-relative source path.
    pub file: &'a str,
    /// Source hash used to produce the findings.
    pub content_hash: &'a str,
    /// Finding-affecting rule configuration fingerprint.
    pub rule_config_hash: &'a str,
}

/// Storage backend for cache entries. [`CacheStore`](super::CacheStore)
/// delegates entry persistence to this trait so that different storage
/// strategies (disk, in-memory, remote) can be swapped without changing
/// the cache lifecycle logic.
pub trait CacheBackend: Send + Sync + std::fmt::Debug {
    /// Read a previously stored entry. Returns `None` when the entry
    /// does not exist or is corrupt.
    fn load_entry(&self, cache_key: &str) -> Option<CacheEntry>;

    /// Persist an entry. Replaces any existing entry with the same key.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the backend cannot persist the entry.
    fn store_entry(&mut self, cache_key: &str, entry: &CacheEntry) -> Result<(), CacheError>;

    /// Persist a borrowed finding slice without forcing every backend to own
    /// a second copy. Backends that store owned values use the compatibility
    /// default; streaming backends can override this method.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the backend cannot persist the entry.
    fn store_entry_borrowed(
        &mut self,
        cache_key: &str,
        schema_version: u32,
        identity: CacheEntryIdentity<'_>,
        findings: &[Finding],
        suppressed_count: usize,
        cached_at: &str,
    ) -> Result<(), CacheError> {
        self.store_entry(
            cache_key,
            &CacheEntry {
                schema_version,
                file: identity.file.to_string(),
                content_hash: identity.content_hash.to_string(),
                rule_config_hash: identity.rule_config_hash.to_string(),
                findings: findings.to_vec(),
                suppressed_count,
                cached_at: cached_at.to_string(),
            },
        )
    }

    /// Remove a single entry. No-op when the key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the backend cannot remove the entry.
    fn delete_entry(&mut self, cache_key: &str) -> Result<(), CacheError>;

    /// Approximate total size of all stored entries in bytes.
    fn total_size(&self) -> u64;

    /// Remove on-disk (or in-memory) entries whose keys are not in
    /// `active_keys`. Returns the number of entries removed.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError`] when the backend cannot enumerate or remove
    /// orphan entries.
    fn clean_orphans(&self, active_keys: &HashSet<&str>) -> Result<usize, CacheError>;
}
