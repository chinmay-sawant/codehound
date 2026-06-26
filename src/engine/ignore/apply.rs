//! Apply parsed `IgnoreDirective`s to a finding vector.

use std::collections::HashMap;

use crate::rules::{Finding, Severity};

use super::directive::IgnoreDirective;

pub fn apply_inline_ignores(
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
            if !finding.message.ends_with(" (suppressed)") {
                finding.message.push_str(" (suppressed)");
            }
            true
        } else {
            false
        }
    });
    suppressed
}

pub fn apply_file_ignore(
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
            if !finding.message.ends_with(" (suppressed)") {
                finding.message.push_str(" (suppressed)");
            }
            true
        } else {
            false
        }
    });
    suppressed
}
