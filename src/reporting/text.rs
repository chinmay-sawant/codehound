//! Plain-text reporter.

use std::collections::BTreeMap;

use anyhow::Result;
use colored::Colorize;

use crate::engine::AnalysisResult;
use crate::rules::Severity;

pub fn print(result: &AnalysisResult) -> Result<()> {
    print_with(result, false)
}

/// Like [`print`] but suppresses the source snippet block.
pub fn print_without_snippet(result: &AnalysisResult) -> Result<()> {
    print_with(result, true)
}

fn print_with(result: &AnalysisResult, suppress_snippet: bool) -> Result<()> {
    if result.findings.is_empty() {
        println!("{}", "no slop detected".green().bold());
        print_summary(result);
        return Ok(());
    }

    for f in &result.findings {
        let sev_colored = color_severity(f.severity);
        let head = format!(
            "{}  {}  {}:{}:{}",
            sev_colored,
            f.rule_id.bold(),
            f.file,
            f.line,
            f.column
        );
        println!("{head}");
        println!("  {}", f.message);
        if !suppress_snippet {
            if let Some(snip) = &f.snippet {
                for line in snip.lines() {
                    println!("    {}", line.dimmed());
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
                println!("  ↳ {}", list.dimmed());
            }
        }
        if let Some(fix) = &f.fix {
            if !fix.is_empty() {
                println!("  fix: {}", fix.cyan());
            }
        }
        println!();
    }

    print_summary(result);
    Ok(())
}

fn color_severity(s: Severity) -> colored::ColoredString {
    let raw = s.as_str();
    match s {
        Severity::Info => raw.cyan(),
        Severity::Warning => raw.yellow(),
        Severity::High => raw.red(),
        Severity::Critical => raw.red().bold(),
    }
}

fn print_summary(result: &AnalysisResult) {
    let n = result.findings.len();
    let mut by_sev: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_rule: BTreeMap<&'static str, usize> = BTreeMap::new();
    for f in &result.findings {
        *by_sev.entry(f.severity.as_str()).or_insert(0) += 1;
        *by_rule.entry(f.rule_id).or_insert(0) += 1;
    }

    if n == 0 {
        return;
    }

    println!("{} finding{}", n, if n == 1 { "" } else { "s" });
    let sev_summary: Vec<String> = by_sev
        .iter()
        .map(|(sev, count)| format!("{count} {sev}"))
        .collect();
    println!("  severity: {}", sev_summary.join(", "));
    let top: Vec<String> = by_rule
        .iter()
        .rev()
        .take(5)
        .map(|(rule, count)| format!("{rule} ×{count}"))
        .collect();
    if !top.is_empty() {
        println!("  top rules: {}", top.join(", "));
    }
    if !result.errors.is_empty() {
        println!("  scan errors: {}", result.errors.len());
    }
}
