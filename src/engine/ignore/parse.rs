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
//! Directives are recognized only inside real line comments (`//` / `#`), never
//! inside string literals (including Go raw strings and Python triple quotes)
//! or block comments (`/* … */`).
//!
//! **Non-goal:** `//nolint` / golangci aliases are not accepted (document as
//! intentional — use `codehound-ignore`).

use std::collections::HashMap;

use super::directive::IgnoreDirective;

const FILE_IGNORE_SCAN_LINES: usize = 20;

/// Line-number (1-based) → directive for inline and expanded block ranges.
pub fn parse_inline_ignores(source: &str) -> HashMap<usize, IgnoreDirective> {
    let Extracted {
        comments,
        code_lines,
    } = extract_line_comments(source);
    let mut ignores: HashMap<usize, IgnoreDirective> = HashMap::new();
    let mut open_blocks: Vec<(usize, IgnoreDirective)> = Vec::new();

    for comment in &comments {
        if let Some(directive) = parse_block_start_body(comment.body) {
            open_blocks.push((comment.line + 1, directive));
            continue;
        }
        if is_block_end_body(comment.body) {
            if let Some((start, directive)) = open_blocks.pop() {
                for ln in start..comment.line {
                    merge_directive(&mut ignores, ln, directive.clone());
                }
            }
            continue;
        }

        if let Some(directive) = parse_ignore_body(comment.body) {
            if comment.has_code_before {
                merge_directive(&mut ignores, comment.line, directive);
            } else if let Some(target_line) = next_code_line(&code_lines, comment.line) {
                merge_directive(&mut ignores, target_line, directive);
            }
        }
    }

    let last = source.lines().count() + 1;
    for (start, directive) in open_blocks {
        for ln in start..last {
            merge_directive(&mut ignores, ln, directive.clone());
        }
    }

    ignores
}

/// Parse a file-level ignore directive from the top of `source`, if present.
pub fn parse_file_ignore(source: &str) -> Option<IgnoreDirective> {
    extract_line_comments(source)
        .comments
        .into_iter()
        .filter(|comment| comment.line <= FILE_IGNORE_SCAN_LINES)
        .find_map(|comment| parse_file_ignore_body(comment.body))
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

struct LineComment<'a> {
    line: usize,
    body: &'a str,
    has_code_before: bool,
}

struct Extracted<'a> {
    comments: Vec<LineComment<'a>>,
    /// 1-based line numbers that contain code outside comments/strings.
    code_lines: Vec<usize>,
}

/// Language-aware scan: emit `//` / `#` line comments only.
///
/// Skips Go/Python string literals (including `` `…` `` and triple quotes) and
/// `/* … */` block comments so directive-like text there cannot forge ignores.
///
/// ponytail: unified Go+Python lexer (no LanguageId / tree-sitter). Ceiling:
/// exotic prefixes (e.g. Python `rf"""`) still close on the matching quote;
/// upgrade to tree-sitter comment nodes if a third language needs different
/// comment syntax.
fn extract_line_comments(source: &str) -> Extracted<'_> {
    let bytes = source.as_bytes();
    let mut comments = Vec::new();
    let mut code_lines = Vec::new();
    let mut line = 1usize;
    let mut line_has_code = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];

        if b == b'\n' {
            if line_has_code {
                code_lines.push(line);
            }
            line += 1;
            line_has_code = false;
            i += 1;
            continue;
        }

        // Line comment: //
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            let body_start = i + 2;
            let body_end = find_line_end(bytes, body_start);
            let body = trim_start_str(&source[body_start..body_end]);
            comments.push(LineComment {
                line,
                body,
                has_code_before: line_has_code,
            });
            i = body_end;
            continue;
        }

        // Block comment: /* … */ (not a directive source)
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i = skip_block_comment(bytes, i + 2, &mut line, &mut line_has_code, &mut code_lines);
            continue;
        }

        // Hash comment (Python); shebang body is ignored by directive parsers.
        if b == b'#' {
            let body_start = i + 1;
            let body_end = find_line_end(bytes, body_start);
            let body = trim_start_str(&source[body_start..body_end]);
            comments.push(LineComment {
                line,
                body,
                has_code_before: line_has_code,
            });
            i = body_end;
            continue;
        }

        // Go raw string: `…`
        if b == b'`' {
            i = skip_raw_string(bytes, i + 1, &mut line, &mut line_has_code, &mut code_lines);
            continue;
        }

        // Triple-quoted strings (Python) or ordinary quotes (Go/Python).
        if b == b'"' || b == b'\'' {
            let quote = b;
            if bytes.get(i + 1) == Some(&quote) && bytes.get(i + 2) == Some(&quote) {
                i = skip_triple_string(
                    bytes,
                    i + 3,
                    quote,
                    &mut line,
                    &mut line_has_code,
                    &mut code_lines,
                );
            } else {
                i = skip_quoted_string(
                    bytes,
                    i + 1,
                    quote,
                    &mut line,
                    &mut line_has_code,
                    &mut code_lines,
                );
            }
            continue;
        }

        if !is_ascii_whitespace(b) {
            line_has_code = true;
        }
        i += 1;
    }

    if line_has_code {
        code_lines.push(line);
    }

    Extracted {
        comments,
        code_lines,
    }
}

fn find_line_end(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    i
}

fn advance_line(line: &mut usize, line_has_code: &mut bool, code_lines: &mut Vec<usize>) {
    if *line_has_code {
        code_lines.push(*line);
        *line_has_code = false;
    }
    *line += 1;
}

fn skip_block_comment(
    bytes: &[u8],
    mut i: usize,
    line: &mut usize,
    line_has_code: &mut bool,
    code_lines: &mut Vec<usize>,
) -> usize {
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            advance_line(line, line_has_code, code_lines);
            i += 1;
            continue;
        }
        if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
            return i + 2;
        }
        i += 1;
    }
    i
}

fn skip_raw_string(
    bytes: &[u8],
    mut i: usize,
    line: &mut usize,
    line_has_code: &mut bool,
    code_lines: &mut Vec<usize>,
) -> usize {
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            advance_line(line, line_has_code, code_lines);
            i += 1;
            continue;
        }
        if bytes[i] == b'`' {
            return i + 1;
        }
        i += 1;
    }
    i
}

fn skip_quoted_string(
    bytes: &[u8],
    mut i: usize,
    quote: u8,
    line: &mut usize,
    line_has_code: &mut bool,
    code_lines: &mut Vec<usize>,
) -> usize {
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            i = (i + 2).min(bytes.len());
            continue;
        }
        if b == b'\n' {
            // Unterminated / multiline interpreted string: keep scanning.
            advance_line(line, line_has_code, code_lines);
            i += 1;
            continue;
        }
        if b == quote {
            return i + 1;
        }
        i += 1;
    }
    i
}

fn skip_triple_string(
    bytes: &[u8],
    mut i: usize,
    quote: u8,
    line: &mut usize,
    line_has_code: &mut bool,
    code_lines: &mut Vec<usize>,
) -> usize {
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            advance_line(line, line_has_code, code_lines);
            i += 1;
            continue;
        }
        if bytes[i] == quote && bytes.get(i + 1) == Some(&quote) && bytes.get(i + 2) == Some(&quote)
        {
            return i + 3;
        }
        i += 1;
    }
    i
}

fn is_ascii_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | 0x0c)
}

fn trim_start_str(s: &str) -> &str {
    s.trim_start()
}

fn parse_ignore_body(body: &str) -> Option<IgnoreDirective> {
    let raw = body.strip_prefix("codehound-ignore:")?.trim();
    parse_rule_list(raw)
}

fn parse_block_start_body(body: &str) -> Option<IgnoreDirective> {
    let raw = body.strip_prefix("codehound-ignore-start")?.trim();
    if raw.is_empty() {
        return Some(IgnoreDirective::all());
    }
    let raw = raw.strip_prefix(':')?.trim();
    if raw.is_empty() {
        return Some(IgnoreDirective::all());
    }
    parse_rule_list(raw)
}

fn is_block_end_body(body: &str) -> bool {
    body.starts_with("codehound-ignore-end")
}

fn parse_file_ignore_body(body: &str) -> Option<IgnoreDirective> {
    let raw = body.strip_prefix("codehound-ignore-file")?.trim();
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

fn next_code_line(code_lines: &[usize], after_line: usize) -> Option<usize> {
    code_lines.iter().copied().find(|&ln| ln > after_line)
}
