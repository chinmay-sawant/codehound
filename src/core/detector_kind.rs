//! Detector execution strategy classification.

/// How a detector derives findings from a parsed unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectorKind {
    /// String/heuristic guards layered on parsed facts (legacy CWE bundle).
    Heuristic,
    /// Primarily driven by precomputed facts (`GoPerfFacts`, `GoUnitFacts`, …).
    FactDriven,
}
