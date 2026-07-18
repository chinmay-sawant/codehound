//! `write_summary` (footer stats) and `write_detector_timing`.

use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;

use crate::Error;
use crate::engine::AnalysisResult;
use crate::export::{ExportOptions, ExportSummary};
use crate::rules::FindingView;

use super::options::TextOptions;

/// Write the compact scan summary used by `--no-terminal`, including export notes.
///
/// # Errors
///
/// Returns [`Error`] when writing to `out` fails.
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
    let mut example_count = 0usize;
    for f in &result.findings {
        let view = FindingView::new(f);
        *by_sev.entry(view.severity().as_str()).or_insert(0) += 1;
        *by_rule.entry(view.rule_id()).or_insert(0) += 1;
        if view
            .non_empty_tags()
            .is_some_and(|tags| tags.iter().any(|t| t == "example"))
        {
            example_count += 1;
        }
    }

    if result.suppressed_count > 0 {
        writeln!(out, "  suppressed findings: {}", result.suppressed_count)?;
    }
    if !result.errors.is_empty() {
        writeln!(out, "  scan errors: {}", result.errors.len())?;
    }

    if let Some(stats) = result.stats.as_ref() {
        let wall = stats
            .timing
            .as_ref()
            .map(|t| t.total_wall_time)
            .unwrap_or(Duration::ZERO);
        writeln!(
            out,
            "scanned {} file{} ({} line{}) in {}",
            stats.files_scanned,
            if stats.files_scanned == 1 { "" } else { "s" },
            stats.lines_scanned,
            if stats.lines_scanned == 1 { "" } else { "s" },
            format_duration(wall),
        )?;
        // Always surface cache vs fresh so a sub-10ms run is not mysterious.
        if stats.cache_hits > 0 || stats.cache_misses > 0 {
            writeln!(
                out,
                "  cache: {} hit{}, {} miss{}{}",
                stats.cache_hits,
                if stats.cache_hits == 1 { "" } else { "s" },
                stats.cache_misses,
                if stats.cache_misses == 1 { "" } else { "es" },
                if stats.cache_hits > 0 && stats.cache_misses == 0 {
                    " (results from cache; not re-analyzed)"
                } else if stats.cache_hits == 0 {
                    " (full re-analysis)"
                } else {
                    ""
                },
            )?;
        }
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
        let msg = if options.color {
            super::style::green_bold("no slop detected").to_string()
        } else {
            "no slop detected".to_string()
        };
        writeln!(out, "{msg}")?;
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
    if example_count > 0 {
        writeln!(out, "  example findings: {example_count} (of {n} total)")?;
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
    // Exclude known parent/wrapper phases that nest other timed work so
    // percentages are not double-counted against leaf detector/rule spans.
    let mut phases: Vec<_> = timing
        .phases
        .iter()
        .filter(|p| !is_wrapper_timing_phase(p.name))
        .collect();
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

fn is_wrapper_timing_phase(name: &str) -> bool {
    matches!(name, "detector_execution")
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

/// Human-readable duration: milliseconds under 1s, seconds otherwise.
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        format!("{:.1}ms", secs * 1000.0)
    } else {
        format!("{secs:.2}s")
    }
}
