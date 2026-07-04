//! `write_with_options`: the main per-finding rendering loop, plus
//! `evidence_summary`.

use std::io::Write;

use crate::Error;
use crate::engine::AnalysisResult;
use crate::rules::DetectorEvidence;

use super::options::TextOptions;
use super::style;
use super::summary::write_summary;

#[must_use = "I/O errors from writing text output must be handled"]
pub fn write_with_options(
    out: &mut impl Write,
    result: &AnalysisResult,
    options: TextOptions,
) -> Result<(), Error> {
    if result.findings.is_empty() {
        writeln!(
            out,
            "{}",
            styled_green_bold("no slop detected", options.color)
        )?;
        write_summary(out, result, options)?;
        return Ok(());
    }

    for f in &result.findings {
        let sev_colored = styled_severity(f.severity, options.color);
        let head = format!(
            "{}  {}  {}:{}:{}",
            sev_colored,
            styled_rule_id(f.rule_id, options.color),
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
                    writeln!(out, "    {}", styled_dimmed(line, options.color))?;
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
                writeln!(out, "  ↳ {}", styled_dimmed(&list, options.color))?;
            }
        }
        if let Some(fix) = &f.fix {
            if !fix.is_empty() {
                writeln!(out, "  fix: {}", styled_cyan(fix, options.color))?;
            }
        }
        writeln!(out)?;
    }

    write_summary(out, result, options)?;

    if options.debug_timing {
        if let Some(stats) = result.stats.as_ref() {
            if let Some(timing) = stats.timing.as_ref() {
                super::summary::write_detector_timing(out, timing)?;
            }
        }
    }

    Ok(())
}

fn styled_severity(severity: crate::rules::Severity, color: bool) -> String {
    if color {
        style::severity(severity).to_string()
    } else {
        severity.as_str().to_string()
    }
}

fn styled_rule_id(rule_id: &str, color: bool) -> String {
    if color {
        style::rule_id(rule_id).to_string()
    } else {
        rule_id.to_string()
    }
}

fn styled_dimmed(text: &str, color: bool) -> String {
    if color {
        style::dimmed(text).to_string()
    } else {
        text.to_string()
    }
}

fn styled_green_bold(text: &str, color: bool) -> String {
    if color {
        style::green_bold(text).to_string()
    } else {
        text.to_string()
    }
}

fn styled_cyan(text: &str, color: bool) -> String {
    if color {
        style::cyan(text).to_string()
    } else {
        text.to_string()
    }
}

pub(super) fn evidence_summary(evidence: &DetectorEvidence) -> String {
    match evidence {
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
        } => {
            let mut s = format!(
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
            );
            for hop in &sink.hop_details {
                s.push_str(&format!(
                    "\n  hop: {}({}) at {}:{}",
                    hop.function, hop.variable, hop.file, hop.line
                ));
            }
            s
        }
        DetectorEvidence::ControlFlowIssue {
            control_flow_kind,
            location,
        } => format!(
            "control-flow issue {control_flow_kind:?} at {}:{}",
            location.line, location.column
        ),
    }
}
