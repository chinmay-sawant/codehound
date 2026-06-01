//! Plain-text reporter.

use anyhow::Result;
use colored::Colorize;

use crate::engine::AnalysisResult;

pub fn print(result: &AnalysisResult) -> Result<()> {
    if result.findings.is_empty() {
        println!("{}", "no slop detected".green().bold());
        return Ok(());
    }

    for f in &result.findings {
        let head = format!(
            "{}  {}  {}:{}:{}",
            f.severity,
            f.rule_id.bold(),
            f.file,
            f.line,
            f.column
        );
        println!("{head}");
        println!("  {}", f.message);
        if let Some(snip) = &f.snippet {
            for line in snip.lines() {
                println!("    {}", line.dimmed());
            }
        }
        if !f.cwe.is_empty() {
            let cwes = f
                .cwe
                .iter()
                .map(|c| format!("CWE-{} ({})", c.id, c.name))
                .collect::<Vec<_>>()
                .join(", ");
            println!("  ↳ {}", cwes.dimmed());
        }
        if let Some(fix) = &f.fix {
            println!("  fix: {}", fix.cyan());
        }
        println!();
    }

    let n = result.findings.len();
    println!("{} finding{}", n, if n == 1 { "" } else { "s" });
    Ok(())
}
