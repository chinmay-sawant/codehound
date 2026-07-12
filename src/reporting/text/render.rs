//! `write_with_options`: the main per-finding rendering loop, plus
//! `evidence_summary`.

use std::io::Write;

use crate::Error;
use crate::cwe::format_cwe_list;
use crate::engine::AnalysisResult;
use crate::rules::{DetectorEvidence, FindingView};

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
        // Summary prints the clean "no slop detected" line (and scan stats).
        write_summary(out, result, options)?;
        return Ok(());
    }

    for f in &result.findings {
        let view = FindingView::new(f);
        let sev_colored = with_color(options.color, f.severity.as_str(), || {
            style::severity(f.severity).to_string()
        });
        let head = format!(
            "{}  {}  {}:{}:{}",
            sev_colored,
            with_color(options.color, f.rule_id, || style::rule_id(f.rule_id)
                .to_string()),
            f.file,
            f.line,
            f.column
        );
        writeln!(out, "{head}")?;
        writeln!(out, "  {}", f.message)?;
        if options.show_fingerprint {
            writeln!(out, "  fingerprint: {}", view.fingerprint())?;
        }
        if let Some(confidence) = view.partial_confidence() {
            writeln!(out, "  confidence: {confidence}")?;
        }
        if let Some(tags) = view.non_empty_tags() {
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
                    writeln!(
                        out,
                        "    {}",
                        with_color(options.color, line, || style::dimmed(line).to_string())
                    )?;
                }
            }
        }
        if let Some(cwes) = view.non_empty_cwe() {
            let list = format_cwe_list(cwes);
            writeln!(
                out,
                "  ↳ {}",
                with_color(options.color, &list, || style::dimmed(&list).to_string())
            )?;
        }
        if let Some(fix) = view.non_empty_fix() {
            writeln!(
                out,
                "  fix: {}",
                with_color(options.color, fix, || style::cyan(fix).to_string())
            )?;
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

fn with_color<T>(color: bool, plain: T, styled: impl FnOnce() -> String) -> String
where
    T: ToString,
{
    if color { styled() } else { plain.to_string() }
}

pub(super) fn evidence_summary(evidence: &DetectorEvidence) -> String {
    match evidence {
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
