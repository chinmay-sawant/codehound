//! In-memory [`CacheBackend`] for tests and ephemeral use.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use super::backend::CacheBackend;
use super::types::{CacheEntry, CacheError};

/// Backend that stores entries in a `HashMap` behind a `Mutex`.
/// Suitable for tests or short-lived cache instances that should not
/// touch the filesystem.
#[derive(Debug)]
pub struct InMemoryBackend {
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl InMemoryBackend {
    pub(super) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl CacheBackend for InMemoryBackend {
    fn load_entry(&self, cache_key: &str) -> Option<CacheEntry> {
        self.entries.lock().unwrap().get(cache_key).cloned()
    }

    fn store_entry(&mut self, cache_key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        self.entries
            .lock()
            .unwrap()
            .insert(cache_key.to_string(), entry.clone());
        Ok(())
    }

    fn delete_entry(&mut self, cache_key: &str) -> Result<(), CacheError> {
        self.entries.lock().unwrap().remove(cache_key);
        Ok(())
    }

    fn total_size(&self) -> u64 {
        self.entries
            .lock()
            .unwrap()
            .values()
            .map(|e| serde_json::to_vec(e).map(|v| v.len() as u64).unwrap_or(0))
            .sum()
    }

    fn clean_orphans(&self, _active_keys: &HashSet<&str>) -> Result<usize, CacheError> {
        // ponytail: in-memory backends never have orphan entries
        // because the manifest and entry store are always in sync.
        Ok(0)
    }
}
