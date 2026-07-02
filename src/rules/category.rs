use super::bp_category::BadPracticeCategory;

/// Coarse rule category derived from the rule ID prefix.
pub fn category_for_rule_id(rule_id: &str) -> &'static str {
    if BadPracticeCategory::from_rule_id(rule_id).is_some() {
        "bad_practice"
    } else if rule_id.starts_with("PERF-") {
        "performance"
    } else if rule_id.starts_with("CWE-") {
        "security"
    } else {
        "general"
    }
}
