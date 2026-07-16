//! Shared single-pass substring index for detector hot paths.
//!
//! Build walks each needle once with `source.contains` (unavoidable). Lookup
//! via [`SourceIndex::has`] is O(1) average using a process-lifetime map keyed
//! by the static needle table pointer — not a linear `position` scan.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Precomputed presence of a static needle table for one source file.
#[derive(Debug, Clone)]
pub struct SourceIndex {
    /// Presence flags in the original needle-table order.
    flags: Vec<bool>,
    /// Shared needle → index map for this needles table (built once per table).
    lookup: &'static NeedleLookup,
}

impl PartialEq for SourceIndex {
    fn eq(&self, other: &Self) -> bool {
        self.flags == other.flags && std::ptr::eq(self.lookup, other.lookup)
    }
}

impl Eq for SourceIndex {}

#[derive(Debug)]
struct NeedleLookup {
    by_name: HashMap<&'static str, usize>,
}

impl Default for SourceIndex {
    fn default() -> Self {
        static EMPTY: OnceLock<NeedleLookup> = OnceLock::new();
        let lookup = EMPTY.get_or_init(|| NeedleLookup {
            by_name: HashMap::new(),
        });
        Self {
            flags: Vec::new(),
            lookup,
        }
    }
}

/// Process-lifetime lookup tables for each distinct `NEEDLES` array.
///
/// Three tables exist in practice (CWE / PERF / BP). Intentional static leak
/// of a few hundred entries — not on the finding hot path.
fn lookup_for(needles: &'static [&'static str]) -> &'static NeedleLookup {
    static CACHE: OnceLock<Mutex<HashMap<usize, &'static NeedleLookup>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = needles.as_ptr() as usize;
    let mut guard = match cache.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(existing) = guard.get(&key) {
        return existing;
    }
    let mut by_name = HashMap::with_capacity(needles.len());
    for (i, needle) in needles.iter().enumerate() {
        // First occurrence wins if a table ever duplicates a string.
        by_name.entry(*needle).or_insert(i);
    }
    let leaked: &'static NeedleLookup = Box::leak(Box::new(NeedleLookup { by_name }));
    guard.insert(key, leaked);
    leaked
}

impl SourceIndex {
    /// One `contains` pass per needle; lookup map is shared across files.
    pub fn build(needles: &'static [&'static str], source: &str) -> Self {
        let flags = needles
            .iter()
            .map(|needle| source.contains(*needle))
            .collect();
        Self {
            flags,
            lookup: lookup_for(needles),
        }
    }

    /// O(1) average membership check. Unknown needles return `false`.
    #[inline]
    pub fn has(&self, needle: &str) -> bool {
        let Some(&idx) = self.lookup.by_name.get(needle) else {
            return false;
        };
        self.flags.get(idx).copied().unwrap_or(false)
    }

    /// True if any of `needles` is present in the indexed source.
    #[inline]
    pub fn has_any(&self, needles: &[&str]) -> bool {
        needles.iter().any(|n| self.has(n))
    }

    /// Number of needles in the backing table (for tests / benches).
    #[inline]
    pub fn len(&self) -> usize {
        self.flags.len()
    }

    /// True when the backing needle table is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[&str] = &["alpha", "beta", "gamma", "sync.Mutex", "select {"];

    #[test]
    fn has_is_true_only_for_present_needles() {
        let idx = SourceIndex::build(SAMPLE, "use sync.Mutex; select { default: }");
        assert!(idx.has("sync.Mutex"));
        assert!(idx.has("select {"));
        assert!(!idx.has("alpha"));
        assert!(!idx.has("missing"));
        assert_eq!(idx.len(), SAMPLE.len());
    }

    #[test]
    fn has_any_short_circuits() {
        let idx = SourceIndex::build(SAMPLE, "gamma only");
        assert!(idx.has_any(&["alpha", "gamma"]));
        assert!(!idx.has_any(&["alpha", "beta"]));
    }

    #[test]
    fn lookup_is_shared_across_builds() {
        let a = SourceIndex::build(SAMPLE, "alpha");
        let b = SourceIndex::build(SAMPLE, "beta");
        // Same static table → same lookup pointer.
        assert!(std::ptr::eq(a.lookup, b.lookup));
        assert!(a.has("alpha"));
        assert!(!a.has("beta"));
        assert!(b.has("beta"));
        assert!(!b.has("alpha"));
    }
}
