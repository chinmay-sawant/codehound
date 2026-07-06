//! Shared assignment-pattern helpers for fact extraction.

/// Split `lhs := rhs`, `lhs = rhs`, or compound assignment (`+=`, `<<=`, …).
pub fn split_assignment(text: &str) -> Option<(&str, &str)> {
    if let Some((lhs, rhs)) = text.split_once(":=") {
        return Some((lhs.trim(), rhs.trim()));
    }
    const COMPOUND: &[&str] = &[
        "<<=", ">>=", "&^=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    ];
    for op in COMPOUND {
        if let Some(idx) = text.find(op) {
            let (lhs, rhs) = text.split_at(idx);
            return Some((lhs.trim(), rhs[op.len()..].trim()));
        }
    }
    let (lhs, rhs) = text.split_once('=')?;
    Some((lhs.trim(), rhs.trim()))
}

/// Extract comma-separated identifier names from an assignment LHS.
pub fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}
