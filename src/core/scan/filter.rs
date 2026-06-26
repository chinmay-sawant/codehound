//! Pattern matching helpers used by `ScanContext::allows`.

pub(super) fn rule_matches(pattern: &str, rule_id: &str) -> bool {
    if pattern == rule_id {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return rule_id.starts_with(prefix);
    }
    false
}
