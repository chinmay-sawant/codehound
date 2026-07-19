//! Detector trait — language-scoped analysis rule.

use crate::core::{LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, RulePack, TimingGranularity};

/// Walks one parsed unit and appends findings.
///
/// # Scan lifecycle
///
/// One top-level analyzer scan owns a detector session:
///
/// 1. **`begin_scan`** — open the session; clears retained project state by default.
/// 2. **`run` / `accumulate_state`** — may execute in parallel across files (Rayon).
///    Must not assume exclusive access to shared process state; write only through
///    carefully locked or thread-local project state. `accumulate_state` also runs
///    for cache-hit files when [`Self::requires_cache_state`] is true.
/// 3. **`finalize`** — single-threaded, after all units. Emit cross-file findings
///    here; merge any per-thread project state first.
/// 4. **`end_scan`** — close the session (also on panic unwind via the engine
///    session guard); clears retained state by default.
///
/// Prefer building project units off-lock and pushing under a short critical
/// section (see Go CWE taint accumulation).
///
/// Panic recovery in the walk path calls [`Self::reset_state`] directly so a
/// single detector failure does not tear down the whole session mid-scan.
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

    /// Product pack this detector belongs to.
    ///
    /// Default: pack of the first rule id (via metadata when present, else id
    /// classification). Multi-rule bundles should override when the pack is a
    /// property of the detector object rather than of individual ids.
    fn pack(&self) -> RulePack {
        let Some(first) = self.rule_ids().first().copied() else {
            return RulePack::General;
        };
        if let Some(meta) = self.metadata_for(first) {
            return meta.pack;
        }
        RulePack::from_rule_id(first)
    }

    /// How debug timing should attribute spans for this detector.
    ///
    /// Default: single-rule → [`TimingGranularity::SingleRule`]; multi-rule →
    /// [`TimingGranularity::DetectorSpan`]. Packs that emit their own per-rule
    /// spans (e.g. bad practices) override with
    /// [`TimingGranularity::PerRuleSelfTimed`].
    fn timing_granularity(&self) -> TimingGranularity {
        TimingGranularity::from_rule_count(self.rule_ids().len())
    }

    /// Stable timing label when using [`TimingGranularity::DetectorSpan`] or
    /// as a fallback span name.
    fn timing_label(&self) -> &'static str {
        self.rule_ids().first().copied().unwrap_or("detector")
    }

    /// Open a scan-scoped session for this detector.
    ///
    /// The engine calls this once at the start of each top-level scan, before
    /// any `run` / `accumulate_state` / `finalize` work. The default clears
    /// retained state via [`Self::reset_state`].
    fn begin_scan(&self, _ctx: &ScanContext) {
        self.reset_state();
    }

    /// Close a scan-scoped session for this detector.
    ///
    /// The engine calls this once when the top-level scan completes or aborts
    /// (including panic cleanup via a session guard). The default clears
    /// retained state via [`Self::reset_state`].
    fn end_scan(&self) {
        self.reset_state();
    }

    /// Run the detector on one parsed unit, appending findings to `out`.
    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>);

    /// Accumulate cross-file analysis state from a parsed unit without
    /// emitting per-file findings. Called for cache-hit files so that
    /// [`finalize`](Self::finalize) has the same state regardless of cache.
    ///
    /// Detector state is scoped to one top-level analyzer scan bounded by
    /// [`Self::begin_scan`] / [`Self::end_scan`]. Implementations retaining
    /// cross-file state must implement the cache-state capability,
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
    /// Called by the default [`Self::begin_scan`] / [`Self::end_scan`]
    /// implementations and by the engine when recovering from a mid-scan
    /// detector panic. Prefer overriding `begin_scan` / `end_scan` only when
    /// session open/close needs more than a clear.
    fn reset_state(&self) {}

    /// Optional: called once after all units have been analyzed.
    /// Detectors can use this to emit cross-file findings.
    /// Default implementation does nothing.
    fn finalize(&self, _ctx: &ScanContext, _out: &mut Vec<Finding>) {}
}
