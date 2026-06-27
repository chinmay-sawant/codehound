//! `write_summary` (footer stats) and `write_detector_timing`.

use std::collections::BTreeMap;
use std::io::Write;

use crate::Error;
use crate::engine::AnalysisResult;

use super::options::TextOptions;

pub(super) fn write_summary(
    out: &mut impl Write,
    result: &AnalysisResult,
    options: TextOptions,
) -> Result<(), Error> {
    let n = result.findings.len();
    let mut by_sev: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_rule: BTreeMap<&'static str, usize> = BTreeMap::new();
    for f in &result.findings {
        *by_sev.entry(f.severity.as_str()).or_insert(0) += 1;
        *by_rule.entry(f.rule_id).or_insert(0) += 1;
    }

    if result.suppressed_count > 0 {
        writeln!(out, "  suppressed findings: {}", result.suppressed_count)?;
    }
    if !result.errors.is_empty() {
        writeln!(out, "  scan errors: {}", result.errors.len())?;
    }

    if let Some(stats) = result.stats.as_ref() {
        writeln!(
            out,
            "scanned {} file{} ({} line{}) in {:.2}s",
            stats.files_scanned,
            if stats.files_scanned == 1 { "" } else { "s" },
            stats.lines_scanned,
            if stats.lines_scanned == 1 { "" } else { "s" },
            stats
                .timing
                .as_ref()
                .map(|t| t.total_wall_time.as_secs_f64())
                .unwrap_or(0.0)
        )?;
        if stats.files_skipped > 0 {
            writeln!(
                out,
                "  skipped {} file{}",
                stats.files_skipped,
                if stats.files_skipped == 1 { "" } else { "s" }
            )?;
        }
        if options.verbose && stats.bytes_scanned > 0 {
            writeln!(out, "  bytes scanned: {}", stats.bytes_scanned)?;
        }
    }

    if n == 0 {
        return Ok(());
    }

    writeln!(out, "{} finding{}", n, if n == 1 { "" } else { "s" })?;
    let sev_summary: Vec<String> = by_sev
        .iter()
        .map(|(sev, count)| format!("{count} {sev}"))
        .collect();
    writeln!(out, "  severity: {}", sev_summary.join(", "))?;
    let mut top_rules: Vec<_> = by_rule.iter().collect();
    top_rules.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let top: Vec<String> = top_rules
        .iter()
        .take(5)
        .map(|(rule, count)| format!("{rule} ×{count}"))
        .collect();
    if !top.is_empty() {
        writeln!(out, "  top rules: {}", top.join(", "))?;
    }

    if options.verbose {
        if let Some(stats) = result.stats.as_ref() {
            if let Some(timing) = stats.timing.as_ref() {
                writeln!(out, "timing:")?;
                for phase in &timing.phases {
                    writeln!(
                        out,
                        "  {:24} {:>8.2}ms  ({:>5.1}%)",
                        phase.name,
                        phase.duration.as_secs_f64() * 1000.0,
                        phase.percentage
                    )?;
                }
            }
        }
    }

    Ok(())
}

pub(super) fn write_detector_timing(
    out: &mut impl Write,
    timing: &crate::engine::TimingSummary,
) -> Result<(), Error> {
    writeln!(out, "--- Detector Timing (top 10) ---")?;
    let mut phases: Vec<_> = timing.phases.iter().collect();
    phases.sort_by_key(|b| std::cmp::Reverse(b.duration));
    let total: std::time::Duration = phases.iter().map(|p| p.duration).sum();
    for phase in phases.iter().take(10) {
        writeln!(
            out,
            "{:<24} {:>8.2}ms  ({:>5.1}%)",
            phase.name,
            phase.duration.as_secs_f64() * 1000.0,
            if total.is_zero() {
                0.0
            } else {
                phase.duration.as_secs_f64() / total.as_secs_f64() * 100.0
            }
        )?;
    }
    writeln!(
        out,
        "Total detector time: {:.2}ms across {} phases",
        total.as_secs_f64() * 1000.0,
        phases.len()
    )?;
    Ok(())
}
