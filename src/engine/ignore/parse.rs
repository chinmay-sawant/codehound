//! Parsing helpers for inline (`// codehound-ignore:`) and file-level
//! (`// codehound-ignore-file`) directives.

use std::collections::HashMap;

use super::directive::IgnoreDirective;

const FILE_IGNORE_SCAN_LINES: usize = 20;

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

fn comment_body(line: &str) -> Option<&str> {
    Some(line.split_once("//")?.1.trim_start())
}

fn parse_ignore_line(line: &str) -> Option<IgnoreDirective> {
    let raw = comment_body(line)?
        .strip_prefix("codehound-ignore:")?
        .trim();
    parse_rule_list(raw)
}

fn parse_file_ignore_line(line: &str) -> Option<IgnoreDirective> {
    let raw = comment_body(line)?
        .strip_prefix("codehound-ignore-file")?
        .trim();
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
