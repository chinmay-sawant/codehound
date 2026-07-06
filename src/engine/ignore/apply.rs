//! Apply parsed `IgnoreDirective`s to a finding vector.

use std::collections::HashMap;

use crate::core::ScanContext;
use crate::rules::{Finding, Severity};

use super::directive::IgnoreDirective;
use super::parse::parse_inline_ignores;

const SUPPRESSED_TAG: &str = " (suppressed)";

fn tag_suppressed(finding: &mut Finding) {
    if !finding.message.ends_with(SUPPRESSED_TAG) {
        finding.message.push_str(SUPPRESSED_TAG);
    }
}

pub(crate) fn apply_inline_ignores(
    findings: &mut Vec<Finding>,
    ignores: &HashMap<usize, IgnoreDirective>,
    show_ignored: bool,
) -> usize {
    if ignores.is_empty() || findings.is_empty() {
        return 0;
    }

    let mut suppressed = 0;
    findings.retain_mut(|finding| {
        let Some(directive) = ignores.get(&finding.line) else {
            return true;
        };
        if !directive.matches(finding.rule_id) {
            return true;
        }

        suppressed += 1;
        if show_ignored {
            finding.severity = Severity::Info;
            finding.suppressed = true;
            tag_suppressed(finding);
            true
        } else {
            false
        }
    });
    suppressed
}

pub(crate) fn apply_file_ignore(
    findings: &mut Vec<Finding>,
    ignore: Option<&IgnoreDirective>,
    show_ignored: bool,
) -> usize {
    let Some(directive) = ignore else {
        return 0;
    };
    apply_directive(
        findings,
        |finding| directive.matches(finding.rule_id),
        show_ignored,
    )
}

fn apply_directive(
    findings: &mut Vec<Finding>,
    should_suppress: impl Fn(&Finding) -> bool,
    show_ignored: bool,
) -> usize {
    if findings.is_empty() {
        return 0;
    }

    let mut suppressed = 0;
    findings.retain_mut(|finding| {
        if !should_suppress(finding) {
            return true;
        }

        suppressed += 1;
        if show_ignored {
            finding.severity = Severity::Info;
            finding.suppressed = true;
            tag_suppressed(finding);
            true
        } else {
            false
        }
    });
    suppressed
}

/// Apply file-level and inline ignore directives to `findings`.
///
/// `file_ignore` should be the result of [`parse_file_ignore`] on `source` when
/// the caller has already parsed it once for the file.
pub(crate) fn apply_ignores(
    ctx: &ScanContext,
    source: &str,
    findings: &mut Vec<Finding>,
    file_ignore: Option<&IgnoreDirective>,
) -> usize {
    if !ctx.show_ignored && file_ignore.is_some_and(IgnoreDirective::is_all) {
        let count = findings.len();
        findings.clear();
        return count;
    }

    let mut suppressed_count = apply_file_ignore(findings, file_ignore, ctx.show_ignored);
    if file_ignore.is_none() {
        let inline_ignores = parse_inline_ignores(source);
        suppressed_count += apply_inline_ignores(findings, &inline_ignores, ctx.show_ignored);
    }
    suppressed_count
}
