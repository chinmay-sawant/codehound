//! Inline suppression comments.

use std::collections::HashMap;

use crate::rules::{Finding, Severity};

const FILE_IGNORE_SCAN_LINES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreDirective {
    rule_ids: Option<Vec<String>>,
}

impl IgnoreDirective {
    pub fn all() -> Self {
        Self { rule_ids: None }
    }

    pub fn rules(rule_ids: Vec<String>) -> Self {
        Self {
            rule_ids: Some(rule_ids),
        }
    }

    pub fn matches(&self, rule_id: &str) -> bool {
        self.rule_ids
            .as_ref()
            .is_none_or(|ids| ids.iter().any(|id| id == rule_id))
    }
}

pub fn parse_inline_ignores(source: &str) -> HashMap<usize, IgnoreDirective> {
    let lines: Vec<&str> = source.lines().collect();
    let mut ignores = HashMap::new();

    for (index, line) in lines.iter().enumerate() {
        let Some(directive) = parse_ignore_line(line) else {
            continue;
        };
        let Some(target_line) = next_non_comment_line(&lines, index + 1) else {
            continue;
        };
        ignores.insert(target_line, directive);
    }

    ignores
}

pub fn parse_file_ignore(source: &str) -> Option<IgnoreDirective> {
    source
        .lines()
        .take(FILE_IGNORE_SCAN_LINES)
        .find_map(parse_file_ignore_line)
}

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

fn parse_ignore_line(line: &str) -> Option<IgnoreDirective> {
    let comment = line.split_once("//")?.1.trim_start();
    let raw = comment.strip_prefix("slopguard-ignore:")?.trim();
    parse_rule_list(raw)
}

fn parse_file_ignore_line(line: &str) -> Option<IgnoreDirective> {
    let comment = line.split_once("//")?.1.trim_start();
    let raw = comment.strip_prefix("slopguard-ignore-file")?.trim();
    if raw.is_empty() {
        return Some(IgnoreDirective::all());
    }
    let raw = raw.strip_prefix(':')?.trim();
    if raw.is_empty() {
        return Some(IgnoreDirective::all());
    }
    parse_rule_list(raw)
}

fn parse_rule_list(raw: &str) -> Option<IgnoreDirective> {
    if raw.eq_ignore_ascii_case("all") {
        return Some(IgnoreDirective::all());
    }

    let rule_ids = raw
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if rule_ids.is_empty() {
        None
    } else {
        Some(IgnoreDirective::rules(rule_ids))
    }
}

fn next_non_comment_line(lines: &[&str], start_index: usize) -> Option<usize> {
    lines
        .iter()
        .enumerate()
        .skip(start_index)
        .find_map(|(index, line)| {
            let trimmed = line.trim();
            (!trimmed.is_empty() && !trimmed.starts_with("//")).then_some(index + 1)
        })
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
