//! In-memory [`CacheBackend`] for tests and ephemeral use.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use super::backend::CacheBackend;
use super::types::{CacheEntry, CacheError};

fn serialized_len(entry: &CacheEntry) -> u64 {
    serde_json::to_vec(entry)
        .map(|v| v.len() as u64)
        .unwrap_or(0)
}

/// Backend that stores entries in a `HashMap` behind a `Mutex`.
/// Suitable for tests or short-lived cache instances that should not
/// touch the filesystem.
#[derive(Debug)]
pub struct InMemoryBackend {
    entries: Mutex<HashMap<String, CacheEntry>>,
    total_bytes: Mutex<u64>,
}

impl InMemoryBackend {
    pub(super) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            total_bytes: Mutex::new(0),
        }
    }
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl CacheBackend for InMemoryBackend {
    fn load_entry(&self, cache_key: &str) -> Option<CacheEntry> {
        lock_or_recover(&self.entries).get(cache_key).cloned()
    }

    fn store_entry(&mut self, cache_key: &str, entry: &CacheEntry) -> Result<(), CacheError> {
        let new_len = serialized_len(entry);
        let mut entries = lock_or_recover(&self.entries);
        let mut total = lock_or_recover(&self.total_bytes);
        if let Some(old) = entries.insert(cache_key.to_string(), entry.clone()) {
            *total = total.saturating_sub(serialized_len(&old));
        }
        *total += new_len;
        Ok(())
    }

    fn delete_entry(&mut self, cache_key: &str) -> Result<(), CacheError> {
        let mut entries = lock_or_recover(&self.entries);
        let mut total = lock_or_recover(&self.total_bytes);
        if let Some(old) = entries.remove(cache_key) {
            *total = total.saturating_sub(serialized_len(&old));
        }
        Ok(())
    }

    fn total_size(&self) -> u64 {
        *lock_or_recover(&self.total_bytes)
    }

    fn clean_orphans(&self, _active_keys: &HashSet<&str>) -> Result<usize, CacheError> {
        // ponytail: in-memory backends never have orphan entries
        // because the manifest and entry store are always in sync.
        Ok(0)
    }
}
