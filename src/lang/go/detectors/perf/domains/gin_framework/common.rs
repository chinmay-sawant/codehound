/// First byte offset containing any of `needles`, or 0 if none match.
pub(crate) fn first_pos(source: &str, needles: &[&str]) -> usize {
    needles
        .iter()
        .filter_map(|n| source.find(n))
        .min()
        .unwrap_or(0)
}

/// Count top-level (depth-0) commas in `s`. Used to size `.Use(...)` arg lists.
pub(crate) fn top_commas(s: &str) -> usize {
    let (mut depth, mut count) = (0i32, 0usize);
    for c in s.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

/// Emit a single PERF finding anchored at `pos` in `unit.source`.
pub(crate) fn emit_at(
    unit: &crate::core::ParsedUnit,
    meta: &'static crate::rules::RuleMetadata,
    pos: usize,
    msg: &str,
    out: &mut Vec<crate::rules::Finding>,
) {
    let (line, col) = unit.line_col(pos);
    crate::rules::emit::push_finding(meta, unit.display_path.as_str(), line, col, msg, out);
}
