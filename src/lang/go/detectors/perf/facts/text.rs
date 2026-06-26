#[doc(hidden)]
pub fn split_assignment(text: &str) -> Option<(&str, &str)> {
    if let Some((lhs, rhs)) = text.split_once(":=") {
        return Some((lhs.trim(), rhs.trim()));
    }
    // Split on the first compound assignment operator (`+=`, `-=`, `<<=`,
    // …) so the operator characters do not leak into the LHS identifier
    // (e.g. `totalDur += d` → LHS = "totalDur", not "totalDur +").
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

#[doc(hidden)]
pub fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}
