//! `write_summary` (footer stats) and `write_detector_timing`.

use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

use crate::Error;
use crate::engine::AnalysisResult;
use crate::export::{ExportOptions, ExportSummary};
use crate::rules::FindingView;

use super::options::TextOptions;

pub fn write_no_terminal_summary(
    out: &mut impl Write,
    result: &AnalysisResult,
    options: TextOptions,
    export_options: &ExportOptions,
    export_summary: &ExportSummary,
) -> Result<(), Error> {
    write_summary(out, result, options)?;

    let mut export_parts = Vec::new();
    if export_options.export_context {
        export_parts.push(format!(
            "exported {} context file(s) to {}",
            export_summary.context_files_written,
            export_options.context_output_dir.display()
        ));
    }
    if export_options.export_chunks {
        export_parts.push(format!(
            "exported {} chunk file(s) to {}",
            export_summary.chunk_files_written,
            export_options.chunks_output_dir.display()
        ));
    }
    if !export_parts.is_empty() {
        writeln!(out, "{}", export_parts.join("; "))?;
    }
    Ok(())
}

pub(crate) fn write_summary(
    out: &mut impl Write,
    result: &AnalysisResult,
    options: TextOptions,
) -> Result<(), Error> {
    let n = result.findings.len();
    let mut by_sev: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_rule: BTreeMap<&'static str, usize> = BTreeMap::new();
    for f in &result.findings {
        let view = FindingView::new(f);
        *by_sev.entry(view.severity().as_str()).or_insert(0) += 1;
        *by_rule.entry(view.rule_id()).or_insert(0) += 1;
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
                    write_phase_timing_line(
                        out,
                        "  ",
                        phase.name,
                        phase.duration,
                        phase.percentage,
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
    let total: Duration = phases.iter().map(|p| p.duration).sum();
    for phase in phases.iter().take(10) {
        let percentage = if total.is_zero() {
            0.0
        } else {
            phase.duration.as_secs_f64() / total.as_secs_f64() * 100.0
        };
        write_phase_timing_line(out, "", phase.name, phase.duration, percentage)?;
    }
    writeln!(
        out,
        "Total detector time: {:.2}ms across {} phases",
        total.as_secs_f64() * 1000.0,
        phases.len()
    )?;
    Ok(())
}

fn write_phase_timing_line(
    out: &mut impl Write,
    indent: &str,
    name: &str,
    duration: Duration,
    percentage: f64,
) -> Result<(), Error> {
    writeln!(
        out,
        "{}{:<24} {:>8.2}ms  ({:>5.1}%)",
        indent,
        name,
        duration.as_secs_f64() * 1000.0,
        percentage
    )?;
    Ok(())
}
