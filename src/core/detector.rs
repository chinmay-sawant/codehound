//! Detector trait — language-scoped analysis rule.

use crate::core::{LanguageId, ParsedUnit, ScanContext};
use crate::rules::Finding;

/// Walks one parsed unit and appends findings.
///
/// # Concurrency model
///
/// 1. **`run`** — may execute in parallel across files (Rayon). Must not
///    assume exclusive access to shared process state; write only through
///    carefully locked or thread-local project state.
/// 2. **`accumulate_state`** — also may run for cache-hit files (often after
///    parallel scan). Same constraints as `run`.
/// 3. **`finalize`** — single-threaded, after all units. Emit cross-file
///    findings here; merge any per-thread project state first.
///
/// Prefer building project units off-lock and pushing under a short critical
/// section (see Go CWE taint accumulation).
pub trait Detector: Send + Sync {
    /// Language this detector analyzes.
    fn language(&self) -> LanguageId;

    /// Rule ids implemented by this detector (one id, or all ids in a language bundle).
    fn rule_ids(&self) -> &'static [&'static str];

    /// Rule metadata for a specific rule id when a detector implements many
    /// rules behind one execution unit.
    fn metadata_for(&self, _rule_id: &str) -> Option<&'static crate::rules::RuleMetadata> {
        None
    }

    /// Run the detector on one parsed unit, appending findings to `out`.
    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>);

    /// Accumulate cross-file analysis state from a parsed unit without
    /// emitting per-file findings. Called for cache-hit files so that
    /// [`finalize`](Self::finalize) has the same state regardless of cache.
    ///
    /// Detector state is scoped to one top-level analyzer scan. The engine
    /// calls [`Self::reset_state`] before and after the scan, and calls
    /// [`Self::finalize`] after per-file work has completed. Implementations
    /// retaining cross-file state must implement the cache-state capability,
    /// accumulation, and reset hooks as one lifecycle protocol. The default
    /// implementation does nothing.
    fn accumulate_state(&self, _ctx: &ScanContext, _unit: &ParsedUnit) {}

    /// Whether cached files must be reparsed and passed to
    /// [`Self::accumulate_state`]. Detectors with cross-file state should
    /// override this together with [`Self::accumulate_state`].
    ///
    /// The default is `false` so stateless detectors do not pay the cache-hit
    /// reparse cost. This is a capability declaration, not a taint-specific
    /// contract.
    fn requires_cache_state(&self, _ctx: &ScanContext) -> bool {
        false
    }

    /// Clear state retained for a project-level analysis.
    ///
    /// The scan engine calls this at both boundaries so a detector cannot
    /// carry project data across an early return or a panic.
    fn reset_state(&self) {}

    /// Optional: called once after all units have been analyzed.
    /// Detectors can use this to emit cross-file findings.
    /// Default implementation does nothing.
    fn finalize(&self, _ctx: &ScanContext, _out: &mut Vec<Finding>) {}
}
