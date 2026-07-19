//! Per-analyzer BP project-fact caches.
//!
//! Each [`super::GoBadPracticeScan`] owns an [`Arc<BpProjectCaches>`]. Free-function
//! detectors and pack-local prewarm reach that instance through a thread-local
//! active session installed for the duration of `begin_scan`…`end_scan` on the
//! controlling thread and for each `run` on Rayon workers. Concurrent analyzers
//! therefore cannot clear or observe each other's maps.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use super::common::ProjectSnapshot;

thread_local! {
    static ACTIVE: RefCell<Option<Arc<BpProjectCaches>>> = const { RefCell::new(None) };
}

/// Scan-scoped project facts memoized for one `GoBadPracticeScan` instance.
pub(crate) struct BpProjectCaches {
    pub(crate) project_snapshots: Mutex<HashMap<PathBuf, ProjectSnapshot>>,
    pub(crate) package_docs: Mutex<HashMap<PathBuf, PackageDocSnapshot>>,
    pub(crate) go_mods: Mutex<HashMap<PathBuf, Option<GoModContext>>>,
    pub(crate) project_imports: Mutex<HashMap<PathBuf, ProjectImports>>,
}

impl BpProjectCaches {
    pub(crate) fn new() -> Self {
        Self {
            project_snapshots: Mutex::new(HashMap::new()),
            package_docs: Mutex::new(HashMap::new()),
            go_mods: Mutex::new(HashMap::new()),
            project_imports: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn clear(&self) {
        self.project_snapshots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.package_docs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.go_mods
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.project_imports
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

/// Package-directory facts for BP-41 (owned by [`BpProjectCaches`]).
#[derive(Clone, Default)]
pub(crate) struct PackageDocSnapshot {
    pub(crate) anchors: HashMap<String, PathBuf>,
    pub(crate) documented_packages: HashSet<String>,
}

/// Parsed `go.mod` text bound to its project root (owned by [`BpProjectCaches`]).
#[derive(Clone)]
pub(crate) struct GoModContext {
    pub(crate) root: PathBuf,
    pub(crate) text: String,
}

/// Import paths collected across a project tree (owned by [`BpProjectCaches`]).
#[derive(Clone, Default)]
pub(crate) struct ProjectImports {
    pub(crate) all: BTreeSet<String>,
    pub(crate) non_test: BTreeSet<String>,
    pub(crate) test_only: BTreeSet<String>,
}

/// Install `caches` as the active session for the current thread until dropped.
///
/// Nested installs restore the previous session (needed when a worker re-enters).
pub(crate) struct ActiveCachesGuard {
    previous: Option<Arc<BpProjectCaches>>,
}

impl ActiveCachesGuard {
    pub(crate) fn install(caches: &Arc<BpProjectCaches>) -> Self {
        let previous = ACTIVE.with(|slot| slot.replace(Some(Arc::clone(caches))));
        Self { previous }
    }
}

impl Drop for ActiveCachesGuard {
    fn drop(&mut self) {
        ACTIVE.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

/// Install active caches for the remainder of the controlling scan thread
/// (until [`clear_active`]). Used by `begin_scan` so `prepare_project` prewarm
/// targets this analyzer's maps.
pub(crate) fn set_active(caches: Arc<BpProjectCaches>) {
    ACTIVE.with(|slot| {
        *slot.borrow_mut() = Some(caches);
    });
}

/// Clear the active session on the current thread.
pub(crate) fn clear_active() {
    ACTIVE.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

/// Borrow the active analyzer's caches, if a session is installed.
pub(crate) fn try_active<R>(f: impl FnOnce(&BpProjectCaches) -> R) -> Option<R> {
    ACTIVE.with(|slot| {
        let guard = slot.borrow();
        guard.as_ref().map(|caches| f(caches.as_ref()))
    })
}

/// Borrow the active analyzer's caches. Panics if no session is active — BP
/// project-fact helpers must only run under `GoBadPracticeScan::run` / prewarm.
pub(crate) fn with_active<R>(f: impl FnOnce(&BpProjectCaches) -> R) -> R {
    try_active(f).expect(
        "BP project caches require an active GoBadPracticeScan session \
         (begin_scan/run must install the analyzer-owned maps)",
    )
}
