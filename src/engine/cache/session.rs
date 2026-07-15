//! [`CacheSession`]: minimal cache surface for scan orchestration.

use std::collections::HashSet;
use std::path::Path;

use crate::Error;
use crate::rules::Finding;

use super::CacheStore;
use super::types::{CacheLookup, CacheManifest};

/// Per-scan cache handle exposing only lookup, write, invalidation, prune,
/// and flush. App-level helpers keep using [`CacheStore`] directly for
/// open, rebuild, and orphan cleanup.
pub struct CacheSession<'a> {
    store: &'a mut CacheStore,
}

impl<'a> CacheSession<'a> {
    /// Begin a scan session over an opened store.
    pub fn open(store: &'a mut CacheStore) -> Self {
        Self { store }
    }

    /// Convenience for callers that hold `Option<&mut CacheStore>`.
    pub fn from_optional(store: Option<&'a mut CacheStore>) -> Option<Self> {
        store.map(Self::open)
    }

    /// Read-only access for cache preflight (lookup, size gates).
    pub fn as_store(&self) -> &CacheStore {
        self.store
    }

    /// Read-only manifest access for hash-change detection.
    pub fn manifest(&self) -> &CacheManifest {
        self.store.manifest()
    }

    /// Ensure this scan's finding-affecting context matches the cache.
    pub fn ensure_rule_config_hash(&mut self, hash: &str) {
        self.store.ensure_rule_config_hash(hash);
    }

    /// Manifest lookup for a file hash.
    pub fn lookup(&self, file: &str, content_hash: &str) -> CacheLookup {
        self.store.lookup(file, content_hash)
    }

    /// Whether a path is eligible for cache reads/writes.
    pub fn should_cache_path(&self, path: &Path) -> bool {
        self.store.should_cache_path(path)
    }

    /// Whether a byte length is eligible for cache writes.
    pub fn should_cache_bytes(&self, size_bytes: u64) -> bool {
        self.store.should_cache_bytes(size_bytes)
    }

    /// Insert or replace a cache entry.
    pub fn put(
        &mut self,
        file: &str,
        content_hash: &str,
        dependencies: &[String],
        findings: Vec<Finding>,
        cached_at: &str,
    ) -> Result<(), Error> {
        self.store.put_with_suppressed_count(
            file,
            content_hash,
            dependencies,
            findings,
            0,
            cached_at,
        )
    }

    /// Insert a cache entry while preserving source-ignore accounting.
    pub fn put_with_suppressed_count(
        &mut self,
        file: &str,
        content_hash: &str,
        dependencies: &[String],
        findings: Vec<Finding>,
        suppressed_count: usize,
        cached_at: &str,
    ) -> Result<(), Error> {
        self.store.put_with_suppressed_count(
            file,
            content_hash,
            dependencies,
            findings,
            suppressed_count,
            cached_at,
        )
    }

    /// Insert a cache entry without cloning findings owned by the scan result.
    pub fn put_with_suppressed_count_borrowed(
        &mut self,
        file: &str,
        content_hash: &str,
        dependencies: &[String],
        findings: &[Finding],
        suppressed_count: usize,
        cached_at: &str,
    ) -> Result<(), Error> {
        self.store.put_with_suppressed_count_borrowed(
            file,
            content_hash,
            dependencies,
            findings,
            suppressed_count,
            cached_at,
        )
    }

    /// Drop a single tracked entry.
    pub fn invalidate_file(&mut self, file: &str) {
        self.store.invalidate_file(file);
    }

    /// Cascade-invalidate dependents of a changed file.
    pub fn invalidate_dependent(&mut self, changed_file: &str) -> usize {
        self.store.invalidate_dependent(changed_file)
    }

    /// Remove entries for files not seen in this scan.
    pub fn prune(&mut self, scanned_files: &HashSet<String>) -> Result<usize, Error> {
        self.store.prune(scanned_files)
    }

    /// Persist dirty manifest and entries.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.store.flush()
    }
}
