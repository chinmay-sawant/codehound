//! Embedder-facing seams: custom registry and cache backend injection.

#![cfg(feature = "go")]

use slopguard::engine::{Analyzer, CacheBackend, CacheEntry, CacheError, CacheStore, Registry};

#[derive(Debug)]
struct EmptyBackend;

impl CacheBackend for EmptyBackend {
    fn load_entry(&self, _cache_key: &str) -> Option<CacheEntry> {
        None
    }

    fn store_entry(&mut self, _cache_key: &str, _entry: &CacheEntry) -> Result<(), CacheError> {
        Ok(())
    }

    fn delete_entry(&mut self, _cache_key: &str) -> Result<(), CacheError> {
        Ok(())
    }

    fn total_size(&self) -> u64 {
        0
    }

    fn clean_orphans(
        &self,
        _active_keys: &std::collections::HashSet<&str>,
    ) -> Result<usize, CacheError> {
        Ok(0)
    }
}

#[test]
fn analyzer_builder_accepts_custom_registry() {
    let registry = Registry::default();
    let analyzer = Analyzer::builder().registry(registry).build();
    let _analyzer = analyzer;
}

#[test]
fn cache_store_with_backend_accepts_custom_impl() {
    let store = CacheStore::with_backend(Box::new(EmptyBackend));
    assert!(store.manifest().files.is_empty());
}
