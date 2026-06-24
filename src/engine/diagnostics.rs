//! Machine-readable scan diagnostics output.

use std::time::SystemTime;

use serde::Serialize;

use crate::engine::ScanStats;
use crate::engine::timing::PhaseTiming;
use crate::rules::Severity;

/// Top-level diagnostics document written when `--diagnostics <FILE>` is used.
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
                files_cached: None,
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

#[derive(Debug, Serialize)]
pub struct ScanDiagnostics {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub files_errored: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_cached: Option<usize>,
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

fn iso8601_utc_now() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let (year, month, day, hour, minute, second) = unix_epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn unix_epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        y as u32,
        m as u32,
        d as u32,
        hour as u32,
        minute as u32,
        second as u32,
    )
}
