/// Internal sub-category assigned to a bad-practice rule id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadPracticeCategory {
    /// Error handling and recovery patterns.
    ErrorHandling,
    /// Concurrency, synchronization, and goroutine lifecycle patterns.
    Concurrency,
    /// Panic and context-propagation patterns tracked with the panic-domain detectors.
    Panics,
    /// Test-only anti-patterns.
    Testing,
    /// Public API design and error-surface patterns.
    ApiDesign,
    /// Package structure and code organization patterns.
    CodeOrganization,
    /// Service lifecycle and production safety patterns.
    ProductionHardening,
    /// Module, dependency, and go.mod hygiene patterns.
    DependencyHygiene,
}

impl BadPracticeCategory {
    /// Map a `BP-*` rule id to its planned bad-practice sub-category.
    pub fn from_rule_id(rule_id: &str) -> Option<Self> {
        let id = rule_id.strip_prefix("BP-")?.parse::<u32>().ok()?;
        match id {
            1 | 2 | 4 | 5 => Some(Self::ErrorHandling),
            3 | 13 | 15 => Some(Self::Panics),
            6..=12 | 14 => Some(Self::Concurrency),
            16..=25 => Some(Self::Testing),
            26..=35 => Some(Self::ApiDesign),
            36..=45 => Some(Self::CodeOrganization),
            46..=55 => Some(Self::ProductionHardening),
            56..=65 => Some(Self::DependencyHygiene),
            _ => None,
        }
    }
}

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
