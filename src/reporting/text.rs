//! Plain-text reporter.

use std::collections::BTreeMap;

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
    print_with(result, false)
}

/// Like [`print`] but suppresses the source snippet block.
pub fn print_without_snippet(result: &AnalysisResult) -> Result<()> {
    print_with(result, true)
}

fn print_with(result: &AnalysisResult, suppress_snippet: bool) -> Result<()> {
    if result.findings.is_empty() {
        println!("{}", style::green_bold("no slop detected"));
        print_summary(result);
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
        println!("{head}");
        println!("  {}", f.message);
        if !suppress_snippet {
            if let Some(snip) = &f.snippet {
                for line in snip.lines() {
                    println!("    {}", style::dimmed(line));
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
                println!("  ↳ {}", style::dimmed(&list));
            }
        }
        if let Some(fix) = &f.fix {
            if !fix.is_empty() {
                println!("  fix: {}", style::cyan(fix));
            }
        }
        println!();
    }

    print_summary(result);
    Ok(())
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
    let mut top_rules: Vec<_> = by_rule.iter().collect();
    top_rules.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    let top: Vec<String> = top_rules
        .iter()
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
