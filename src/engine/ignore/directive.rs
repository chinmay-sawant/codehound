//! Suppression directive: rule list or "all rules".
//!
//! Used for next-line, EOL, file-level, and block-range ignores.

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
