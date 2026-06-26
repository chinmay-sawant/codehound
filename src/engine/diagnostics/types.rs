//! Sub-structs for the `Diagnostics` document.

use serde::Serialize;

use crate::engine::timing::PhaseTiming;

#[derive(Debug, Serialize)]
pub struct ScanDiagnostics {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub files_errored: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_cached: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_fresh: Option<usize>,
    pub bytes_scanned: u64,
    pub lines_scanned: u64,
    pub duration_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct FindingsDiagnostics {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub suppressed: usize,
}

#[derive(Debug, Serialize)]
pub struct TimingDiagnostics {
    pub phases: Vec<PhaseTiming>,
}

#[derive(Debug, Serialize)]
pub struct DetectorsDiagnostics {
    pub loaded: usize,
    pub executed: usize,
    pub top_by_time: Vec<RuleTiming>,
}

#[derive(Debug, Serialize)]
pub struct RuleTiming {
    pub rule: String,
    pub duration_ms: f64,
}
