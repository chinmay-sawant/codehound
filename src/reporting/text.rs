//! Plain-text reporter.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::Result;

use crate::engine::AnalysisResult;
use crate::rules::DetectorEvidence;

#[cfg(feature = "terminal-output")]
mod style {
    use crate::rules::Severity;
    use colored::Colorize;

    pub fn severity(s: Severity) -> colored::ColoredString {
        let raw = s.as_str();
        match s {
            Severity::Info => raw.cyan(),
            Severity::Low => raw.yellow(),
            Severity::Medium => raw.yellow().bold(),
            Severity::High => raw.red(),
            Severity::Critical => raw.red().bold(),
        }
    }

    pub fn rule_id(s: &str) -> colored::ColoredString {
        if s.starts_with("BP-") {
            s.magenta().bold()
        } else if s.starts_with("PERF-") {
            s.cyan().bold()
        } else {
            s.bold()
        }
    }
    pub fn dimmed(s: &str) -> colored::ColoredString {
        s.dimmed()
    }
    pub fn green_bold(s: &str) -> colored::ColoredString {
        s.green().bold()
    }
    pub fn cyan(s: &str) -> colored::ColoredString {
        s.cyan()
    }
}

#[cfg(not(feature = "terminal-output"))]
mod style {
    use crate::rules::Severity;

    pub fn severity(s: Severity) -> &'static str {
        s.as_str()
    }
    pub fn rule_id(s: &str) -> &str {
        s
    }
    pub fn dimmed(s: &str) -> &str {
        s
    }
    pub fn green_bold(s: &str) -> &str {
        s
    }
    pub fn cyan(s: &str) -> &str {
        s
    }
}

pub fn print(result: &AnalysisResult) -> Result<()> {
    print_with_options(result, TextOptions::default())
}

/// Like [`print`] but suppresses the source snippet block.
pub fn print_without_snippet(result: &AnalysisResult) -> Result<()> {
    print_with_options(
        result,
        TextOptions {
            suppress_snippet: true,
            ..TextOptions::default()
        },
    )
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TextOptions {
    pub suppress_snippet: bool,
    pub show_fingerprint: bool,
    pub verbose: bool,
    pub debug_timing: bool,
}

pub fn print_with_options(result: &AnalysisResult, options: TextOptions) -> Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_with_options(&mut out, result, options)
}

pub fn write_with_options(
    out: &mut impl Write,
    result: &AnalysisResult,
    options: TextOptions,
) -> Result<()> {
    if result.findings.is_empty() {
        writeln!(out, "{}", style::green_bold("no slop detected"))?;
        write_summary(out, result, options)?;
        return Ok(());
    }

    for f in &result.findings {
        let sev_colored = style::severity(f.severity);
        let head = format!(
            "{}  {}  {}:{}:{}",
            sev_colored,
            style::rule_id(f.rule_id),
            f.file,
            f.line,
            f.column
        );
        writeln!(out, "{head}")?;
        writeln!(out, "  {}", f.message)?;
        if options.show_fingerprint {
            writeln!(out, "  fingerprint: {}", f.fingerprint_string())?;
        }
        if let Some(confidence) = f.confidence.filter(|confidence| *confidence < 1.0) {
            writeln!(out, "  confidence: {confidence}")?;
        }
        if let Some(tags) = f.tags.as_deref().filter(|tags| !tags.is_empty()) {
            writeln!(out, "  tags: {}", tags.join(", "))?;
        }
        if f.suppressed {
            writeln!(out, "  status: suppressed")?;
        }
        if options.verbose {
            if let Some(evidence) = &f.evidence {
                writeln!(out, "  evidence: {}", evidence_summary(evidence))?;
            }
        }
        if !options.suppress_snippet {
            if let Some(snip) = &f.snippet {
                for line in snip.lines() {
                    writeln!(out, "    {}", style::dimmed(line))?;
                }
            }
        }
        if let Some(cwes) = f.cwe.as_deref() {
            if !cwes.is_empty() {
                let mut sorted: Vec<_> = cwes.iter().collect();
                sorted.sort_by_key(|c| c.id);
                let list = sorted
                    .iter()
                    .map(|c| format!("CWE-{} ({})", c.id, c.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(out, "  ↳ {}", style::dimmed(&list))?;
            }
        }
        if let Some(fix) = &f.fix {
            if !fix.is_empty() {
                writeln!(out, "  fix: {}", style::cyan(fix))?;
            }
        }
        writeln!(out)?;
    }

    write_summary(out, result, options)?;

    if options.debug_timing {
        if let Some(stats) = result.stats.as_ref() {
            if let Some(timing) = stats.timing.as_ref() {
                write_detector_timing(out, timing)?;
            }
        }
    }

    Ok(())
}

fn evidence_summary(evidence: &DetectorEvidence) -> String {
    match evidence {
        DetectorEvidence::PatternMatch {
            pattern,
            match_location,
        } => format!(
            "pattern `{pattern}` at {}:{}",
            match_location.line, match_location.column
        ),
        DetectorEvidence::DangerousCall {
            function,
            argument_index,
        } => match argument_index {
            Some(index) => format!("dangerous call `{function}` argument {index}"),
            None => format!("dangerous call `{function}`"),
        },
        DetectorEvidence::TaintFlow {
            source,
            sink,
            hops,
            sanitized,
        } => format!(
            "taint flow {}.{} -> {}.{} across {hops} hop{}{}",
            source.kind,
            source.function,
            sink.kind,
            sink.function,
            if *hops == 1 { "" } else { "s" },
            if *sanitized {
                " with sanitizer evidence"
            } else {
                ""
            }
        ),
        DetectorEvidence::MissingConfig { struct_name, field } => {
            format!("missing config `{struct_name}.{field}`")
        }
        DetectorEvidence::ControlFlowIssue {
            control_flow_kind,
            location,
        } => format!(
            "control-flow issue {control_flow_kind:?} at {}:{}",
            location.line, location.column
        ),
        DetectorEvidence::Other { .. } => "custom detector evidence".to_string(),
    }
}

fn write_summary(
    out: &mut impl Write,
    result: &AnalysisResult,
    options: TextOptions,
) -> Result<()> {
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

fn write_detector_timing(
    out: &mut impl Write,
    timing: &crate::engine::TimingSummary,
) -> Result<()> {
    writeln!(out, "--- Detector Timing (top 10) ---")?;
    let mut phases: Vec<_> = timing.phases.iter().collect();
    phases.sort_by(|a, b| b.duration.cmp(&a.duration));
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
