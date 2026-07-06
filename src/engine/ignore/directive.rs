//! Inline suppression directive: a single `// slopguard-ignore: CWE-22, CWE-78`
//! marker targeting the next non-comment line, or a file-level header.

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

    pub fn is_all(&self) -> bool {
        self.rule_ids.is_none()
    }
}
