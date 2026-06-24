//! Plain-text reporter.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anyhow::Result;

use crate::engine::AnalysisResult;

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

    pub fn bold(s: &str) -> colored::ColoredString {
        s.bold()
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
    pub fn bold(s: &str) -> &str {
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
        write_summary(out, result)?;
        return Ok(());
    }

    for f in &result.findings {
        let sev_colored = style::severity(f.severity);
        let head = format!(
            "{}  {}  {}:{}:{}",
            sev_colored,
            style::bold(f.rule_id),
            f.file,
            f.line,
            f.column
        );
        writeln!(out, "{head}")?;
        writeln!(out, "  {}", f.message)?;
        if options.show_fingerprint {
            writeln!(out, "  fingerprint: {}", f.fingerprint_string())?;
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

    write_summary(out, result)?;
    Ok(())
}

fn write_summary(out: &mut impl Write, result: &AnalysisResult) -> Result<()> {
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
    Ok(())
}
