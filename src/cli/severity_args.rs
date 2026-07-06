//! `SeverityArgs`: CLI exit-policy flags.

use clap::Args;

use crate::core::FailPolicy;

#[derive(Debug, Clone, Copy, Args)]
#[group(multiple = false)]
pub struct SeverityArgs {
    /// Exit non-zero on warnings (default).
    // ponytail: dead — fail_policy() always returns MediumAsErrors regardless
    // of this flag; kept to avoid breaking the CLI interface.
    #[arg(long)]
    pub warnings_as_errors: bool,

    /// Only fail on high-severity findings.
    #[arg(long)]
    pub strict: bool,

    /// Never fail the run.
    #[arg(long)]
    pub no_fail: bool,
}

impl SeverityArgs {
    pub fn fail_policy(self) -> FailPolicy {
        if self.no_fail {
            FailPolicy::NoFail
        } else if self.strict {
            FailPolicy::Strict
        } else {
            FailPolicy::MediumAsErrors
        }
    }

    /// True iff the user explicitly chose a severity policy on the CLI.
    pub fn is_explicit(self) -> bool {
        self.no_fail || self.strict || self.warnings_as_errors
    }
}
