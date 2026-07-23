//! Optional Go typed / package-graph facts (G4).
//!
//! Tree-sitter remains the primary analysis path. When `--typed` is on and a Go
//! toolchain is available, this module loads package identity via `go list -json`
//! once per project root and exposes it through a session side channel.
//! Detectors may consult facts; missing facts must behave like tree-sitter-only.

mod load;
mod session;

pub use load::{TypedLoadStatus, load_project_facts};
pub use session::{
    ActiveTypedGuard, TypedFacts, clear_active, package_path_for_file, set_active, status,
    try_active,
};

use std::sync::Arc;

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, RulePack, TimingGranularity};

/// Session owner for typed facts (begin_scan → prepare_project fill → end_scan).
pub struct GoTypedScan {
    facts: Arc<TypedFacts>,
}

impl GoTypedScan {
    /// Create a session owner with empty facts.
    pub fn new() -> Self {
        Self {
            facts: Arc::new(TypedFacts::new()),
        }
    }
}

impl Default for GoTypedScan {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for GoTypedScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        // Session-only detector: no findings.
        &[]
    }

    fn pack(&self) -> RulePack {
        RulePack::General
    }

    fn timing_granularity(&self) -> TimingGranularity {
        TimingGranularity::DetectorSpan
    }

    fn timing_label(&self) -> &'static str {
        "go-typed-session"
    }

    fn begin_scan(&self, ctx: &ScanContext) {
        self.facts.clear();
        if ctx.typed_enabled {
            session::set_active(Arc::clone(&self.facts));
        } else {
            session::clear_active();
        }
    }

    fn end_scan(&self) {
        session::clear_active();
        self.facts.clear();
    }

    fn reset_state(&self) {
        self.facts.clear();
    }

    fn run(&self, _ctx: &ScanContext, _unit: &ParsedUnit, _out: &mut Vec<Finding>) {
        // Session-only; facts are filled in prepare_project.
    }
}

/// Fill active typed facts for each project root (called from Go plugin prepare).
pub(crate) fn prepare_typed_facts(ctx: &ScanContext, project_roots: &[&std::path::Path]) {
    if !ctx.typed_enabled {
        return;
    }
    let Some(facts) = try_active(Arc::clone) else {
        tracing::debug!("typed enabled but no active typed session; skip load");
        return;
    };
    for root in project_roots {
        load::load_into(&facts, root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn package_path_absent_when_session_off() {
        clear_active();
        assert!(package_path_for_file(Path::new("/x/main.go")).is_none());
        assert_eq!(status(), TypedLoadStatus::Off);
    }

    #[test]
    fn load_without_go_records_unavailable() {
        let facts = TypedFacts::new();
        // Empty root: go list fails or returns nothing useful.
        let status = load_project_facts(Path::new("/nonexistent-codehound-typed-root-xyz"), &facts);
        assert!(matches!(
            status,
            TypedLoadStatus::Unavailable(_) | TypedLoadStatus::Ready { .. }
        ));
    }
}
