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
    fn language(&self) -> LanguageId;

    /// Rule ids implemented by this detector (one id, or all ids in a language bundle).
    fn rule_ids(&self) -> &'static [&'static str];

    /// Rule metadata for a specific rule id when a detector implements many
    /// rules behind one execution unit.
    fn metadata_for(&self, rule_id: &str) -> Option<&'static crate::rules::RuleMetadata> {
        let _ = rule_id;
        None
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>);

    /// Accumulate cross-file analysis state from a parsed unit without
    /// emitting per-file findings. Called for cache-hit files so that
    /// [`finalize`](Self::finalize) has the same state regardless of cache.
    /// Default implementation does nothing.
    fn accumulate_state(&self, _ctx: &ScanContext, _unit: &ParsedUnit) {}

    /// Optional: called once after all units have been analyzed.
    /// Detectors can use this to emit cross-file findings.
    /// Default implementation does nothing.
    fn finalize(&self, _ctx: &ScanContext, _out: &mut Vec<Finding>) {}
}
