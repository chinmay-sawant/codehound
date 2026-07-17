//! Suppression directive: rule list or "all rules".
//!
//! Used for next-line, EOL, file-level, and block-range ignores.

/// Suppression directive: a rule allow-list or “all rules”.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoreDirective {
    rule_ids: Option<Vec<String>>,
}

impl IgnoreDirective {
    /// Suppress every rule.
    pub fn all() -> Self {
        Self { rule_ids: None }
    }

    /// Suppress only the listed rule IDs.
    pub fn rules(rule_ids: Vec<String>) -> Self {
        Self {
            rule_ids: Some(rule_ids),
        }
    }

    /// Whether this directive suppresses `rule_id`.
    pub fn matches(&self, rule_id: &str) -> bool {
        self.rule_ids
            .as_ref()
            .is_none_or(|ids| ids.iter().any(|id| id == rule_id))
    }

    /// True when every rule is suppressed.
    pub fn is_all(&self) -> bool {
        self.rule_ids.is_none()
    }

    /// Union with another directive (`all` wins).
    pub fn merge(&mut self, other: IgnoreDirective) {
        match (&mut self.rule_ids, other.rule_ids) {
            (None, _) | (_, None) => {
                self.rule_ids = None;
            }
            (Some(a), Some(b)) => {
                for id in b {
                    if !a.iter().any(|x| x == &id) {
                        a.push(id);
                    }
                }
            }
        }
    }
}
