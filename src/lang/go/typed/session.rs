//! Scan-scoped typed-fact session (shared across Rayon workers).
//!
//! # Concurrent analyzers
//! `Analyzer` serializes top-level scans per instance. A process-global slot is
//! used so workers can read facts without per-detector install. Two Analyzers
//! scanning in parallel would race — same limitation as other process-global
//! scan hooks; use one Analyzer per concurrent scan owner.
//!
//! // ponytail: global slot OK while Analyzer serializes; per-analyzer map if multi-scan throughput matters

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use super::load::TypedLoadStatus;

fn slot() -> &'static Mutex<Option<Arc<TypedFacts>>> {
    static SLOT: OnceLock<Mutex<Option<Arc<TypedFacts>>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

/// Scan-scoped package identity facts from optional `go list`.
pub struct TypedFacts {
    /// Absolute canonical file path → import path.
    by_file: Mutex<HashMap<PathBuf, String>>,
    status: Mutex<TypedLoadStatus>,
}

impl TypedFacts {
    /// Empty fact store.
    pub fn new() -> Self {
        Self {
            by_file: Mutex::new(HashMap::new()),
            status: Mutex::new(TypedLoadStatus::Off),
        }
    }

    /// Drop all indexed files and reset status to [`TypedLoadStatus::Off`].
    pub fn clear(&self) {
        self.by_file
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        *self.status.lock().unwrap_or_else(|p| p.into_inner()) = TypedLoadStatus::Off;
    }

    /// Record load outcome for diagnostics.
    pub fn set_status(&self, status: TypedLoadStatus) {
        *self.status.lock().unwrap_or_else(|p| p.into_inner()) = status;
    }

    /// Current load outcome.
    pub fn status(&self) -> TypedLoadStatus {
        self.status
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Map a source file to its `go list` import path.
    pub fn insert_file(&self, file: PathBuf, pkg_path: String) {
        self.by_file
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(file, pkg_path);
    }

    /// Lookup import path for `file` (exact or canonicalized path).
    pub fn package_path_for_file(&self, file: &Path) -> Option<String> {
        let map = self.by_file.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(p) = map.get(file) {
            return Some(p.clone());
        }
        let canon = file.canonicalize().ok()?;
        map.get(&canon).cloned()
    }

    /// Number of indexed Go files.
    pub fn file_count(&self) -> usize {
        self.by_file.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

impl Default for TypedFacts {
    fn default() -> Self {
        Self::new()
    }
}

/// Install facts for the remainder of the scan (workers included).
pub fn set_active(facts: Arc<TypedFacts>) {
    *slot().lock().unwrap_or_else(|p| p.into_inner()) = Some(facts);
}

/// Clear the active scan facts.
pub fn clear_active() {
    *slot().lock().unwrap_or_else(|p| p.into_inner()) = None;
}

/// Run `f` with the active scan facts, if any.
pub fn try_active<R>(f: impl FnOnce(&Arc<TypedFacts>) -> R) -> Option<R> {
    let guard = slot().lock().unwrap_or_else(|p| p.into_inner());
    guard.as_ref().map(f)
}

/// Package import path for `file` when typed session is active and loaded.
pub fn package_path_for_file(file: &Path) -> Option<String> {
    try_active(|facts| facts.package_path_for_file(file)).flatten()
}

/// Current typed load status (Off when no session).
pub fn status() -> TypedLoadStatus {
    try_active(|facts| facts.status()).unwrap_or(TypedLoadStatus::Off)
}

/// RAII install for tests / nested scopes.
pub struct ActiveTypedGuard {
    previous: Option<Arc<TypedFacts>>,
}

impl ActiveTypedGuard {
    /// Install `facts` until this guard drops (restores previous).
    pub fn install(facts: &Arc<TypedFacts>) -> Self {
        let previous = slot()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .replace(Arc::clone(facts));
        Self { previous }
    }
}

impl Drop for ActiveTypedGuard {
    fn drop(&mut self) {
        *slot().lock().unwrap_or_else(|p| p.into_inner()) = self.previous.take();
    }
}
