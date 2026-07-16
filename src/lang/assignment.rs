//! Shared assignment-pattern helpers for fact extraction.

/// Split `lhs := rhs`, `lhs = rhs`, or compound assignment (`+=`, `<<=`, …).
pub fn split_assignment(text: &str) -> Option<(&str, &str)> {
    let (mut lhs, rhs) = text.split_once('=')?;
    for prefix in &[
        "<<", ">>", "&^", "+", "-", "*", "/", "%", "&", "|", "^", ":",
    ] {
        if lhs.ends_with(prefix) {
            lhs = &lhs[..lhs.len() - prefix.len()];
            break;
        }
    }
    Some((lhs.trim(), rhs.trim()))
}

/// Extract comma-separated identifier names from an assignment LHS.
pub fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}
