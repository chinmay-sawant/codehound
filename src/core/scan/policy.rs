//! When the CLI should exit non-zero based on finding severity.

use crate::rules::Severity;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FailPolicy {
    /// Fail on medium, high, or critical (default).
    #[default]
    MediumAsErrors,
    /// Fail only on high or critical.
    Strict,
    /// Always exit 0 for findings.
    NoFail,
}

impl FailPolicy {
    pub fn should_fail(self, severity: Severity) -> bool {
        match self {
            Self::NoFail => false,
            Self::Strict => matches!(severity, Severity::High | Severity::Critical),
            Self::MediumAsErrors => severity.is_failure(),
        }
    }
}
