//! Top-level `Diagnostics` document and its `from_stats` constructor.

use serde::Serialize;

use crate::engine::ScanStats;
use crate::rules::Severity;

use super::clock::iso8601_utc_now;
use super::types::{
    DetectorsDiagnostics, FindingsDiagnostics, RuleTiming, ScanDiagnostics, TimingDiagnostics,
};

#[derive(Debug, Serialize)]
pub struct Diagnostics {
    pub tool: &'static str,
    pub version: &'static str,
    pub timestamp: String,
    pub scan: ScanDiagnostics,
    pub findings: FindingsDiagnostics,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<TimingDiagnostics>,
    pub detectors: DetectorsDiagnostics,
}

impl Diagnostics {
    pub fn from_stats(stats: &ScanStats) -> Self {
        let duration_ms = stats
            .timing
            .as_ref()
            .map(|t| t.total_wall_time.as_secs_f64() * 1000.0)
            .unwrap_or(0.0);

        Self {
            tool: "slopguard",
            version: env!("CARGO_PKG_VERSION"),
            timestamp: iso8601_utc_now(),
            scan: ScanDiagnostics {
                files_scanned: stats.files_scanned,
                files_skipped: stats.files_skipped,
                files_errored: stats.files_errored,
                files_cached: Some(stats.cache_hits),
                files_fresh: Some(stats.cache_misses),
                bytes_scanned: stats.bytes_scanned,
                lines_scanned: stats.lines_scanned,
                duration_ms,
            },
            findings: FindingsDiagnostics {
                total: stats.findings_total,
                critical: *stats
                    .findings_by_severity
                    .get(Severity::Critical.as_str())
                    .unwrap_or(&0),
                high: *stats
                    .findings_by_severity
                    .get(Severity::High.as_str())
                    .unwrap_or(&0),
                medium: *stats
                    .findings_by_severity
                    .get(Severity::Medium.as_str())
                    .unwrap_or(&0),
                low: *stats
                    .findings_by_severity
                    .get(Severity::Low.as_str())
                    .unwrap_or(&0),
                info: *stats
                    .findings_by_severity
                    .get(Severity::Info.as_str())
                    .unwrap_or(&0),
                suppressed: stats.findings_suppressed,
            },
            timing: stats.timing.as_ref().map(|summary| TimingDiagnostics {
                phases: summary.phases.clone(),
            }),
            detectors: DetectorsDiagnostics {
                loaded: stats.detectors_loaded,
                executed: stats.rules_executed,
                top_by_time: stats
                    .timing
                    .as_ref()
                    .map(|summary| {
                        summary
                            .phases
                            .iter()
                            .map(|phase| RuleTiming {
                                rule: phase.name.to_string(),
                                duration_ms: phase.duration.as_secs_f64() * 1000.0,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            },
        }
    }
}
