//! Parsing helpers for inline, block, EOL, and file-level ignore directives.
//!
//! Supported comment styles:
//! - Go / C-like: `// codehound-ignore: …`
//! - Python: `# codehound-ignore: …`
//!
//! Directives:
//! - `codehound-ignore: RULES` — next non-comment line (or same line if EOL)
//! - `codehound-ignore-file[: RULES]` — whole file (header)
//! - `codehound-ignore-start: RULES` … `codehound-ignore-end` — block range
//!
//! **Non-goal:** `//nolint` / golangci aliases are not accepted (document as
//! intentional — use `codehound-ignore`).

use std::collections::HashMap;

use super::directive::IgnoreDirective;

const FILE_IGNORE_SCAN_LINES: usize = 20;

/// Line-number (1-based) → directive for inline and expanded block ranges.
pub fn parse_inline_ignores(source: &str) -> HashMap<usize, IgnoreDirective> {
    let lines: Vec<&str> = source.lines().collect();
    let mut ignores: HashMap<usize, IgnoreDirective> = HashMap::new();

    // Block ranges: (start_line_1based_inclusive, directive)
    let mut open_blocks: Vec<(usize, IgnoreDirective)> = Vec::new();

    for (index, line) in lines.iter().enumerate() {
        let line_no = index + 1;

        if let Some(directive) = parse_block_start(line) {
            open_blocks.push((line_no + 1, directive));
            continue;
        }
        if is_block_end(line) {
            if let Some((start, directive)) = open_blocks.pop() {
                // Range covers code lines from start through previous line.
                for ln in start..line_no {
                    merge_directive(&mut ignores, ln, directive.clone());
                }
            }
            continue;
        }

        if let Some(directive) = parse_ignore_line(line) {
            if has_code_before_comment(line) {
                // Trailing end-of-line ignore applies to this line.
                merge_directive(&mut ignores, line_no, directive);
            } else if let Some(target_line) = next_code_line(&lines, index + 1) {
                merge_directive(&mut ignores, target_line, directive);
            }
        }
    }

    // Unclosed blocks: apply through EOF.
    let last = lines.len() + 1;
    for (start, directive) in open_blocks {
        for ln in start..last {
            merge_directive(&mut ignores, ln, directive.clone());
        }
    }

    ignores
}

pub fn parse_file_ignore(source: &str) -> Option<IgnoreDirective> {
    source
        .lines()
        .take(FILE_IGNORE_SCAN_LINES)
        .find_map(parse_file_ignore_line)
}

fn merge_directive(
    map: &mut HashMap<usize, IgnoreDirective>,
    line: usize,
    directive: IgnoreDirective,
) {
    match map.get_mut(&line) {
        Some(existing) => existing.merge(directive),
        None => {
            map.insert(line, directive);
        }
    }
}

fn find_comment_start(line: &str) -> Option<(usize, char)> {
    let mut in_double_quote = false;
    let mut in_single_quote = false;
    let mut escaped = false;
    let mut chars = line.char_indices().peekable();
    while let Some((byte_idx, c)) = chars.next() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
        } else if c == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
        } else if !in_double_quote && !in_single_quote {
            if c == '/' && chars.peek().is_some_and(|(_, next)| *next == '/') {
                return Some((byte_idx, '/'));
            }
            if c == '#' {
                return Some((byte_idx, '#'));
            }
        }
    }
    None
}

/// Extract comment body after `//` or `#` (not shebang).
fn comment_body(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("#!") {
        return None;
    }
    if let Some((idx, kind)) = find_comment_start(line) {
        if kind == '/' {
            Some(line[idx + 2..].trim_start())
        } else {
            Some(line[idx + 1..].trim_start())
        }
    } else {
        None
    }
}

fn has_code_before_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('#') {
        return false;
    }
    if let Some((idx, _)) = find_comment_start(line) {
        return !line[..idx].trim().is_empty();
    }
    false
}

fn parse_ignore_line(line: &str) -> Option<IgnoreDirective> {
    let raw = comment_body(line)?
        .strip_prefix("codehound-ignore:")?
        .trim();
    parse_rule_list(raw)
}

fn parse_block_start(line: &str) -> Option<IgnoreDirective> {
    let raw = comment_body(line)?
        .strip_prefix("codehound-ignore-start")?
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

fn is_block_end(line: &str) -> bool {
    comment_body(line).is_some_and(|b| b.starts_with("codehound-ignore-end"))
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

fn next_code_line(lines: &[&str], start_index: usize) -> Option<usize> {
    lines
        .iter()
        .enumerate()
        .skip(start_index)
        .find_map(|(index, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            if trimmed.starts_with("//") || trimmed.starts_with('#') {
                return None;
            }
            Some(index + 1)
        })
}
