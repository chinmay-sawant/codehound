//! CLI enums: `Command`, `LangMode`, `OutputFormat`, `RuleCategory`, `ProfileArg`.

use clap::{Subcommand, ValueEnum};

use crate::core::{LanguageId, ScanProfile};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a starter `codehound.toml` to the current directory.
    Init,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum LangMode {
    #[default]
    Auto,
    Go,
    Python,
}

impl LangMode {
    pub fn language_id(self) -> Option<LanguageId> {
        match self {
            LangMode::Auto => None,
            LangMode::Go => Some(LanguageId::Go),
            LangMode::Python => Some(LanguageId::Python),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
}

/// Product pack for high-signal defaults (`--profile`).
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq, Default)]
pub enum ProfileArg {
    /// Curated CI pack (default): S-tier PERF + taint-core CWEs.
    #[default]
    Recommended,
    /// Framework + hot-path PERF.
    Perf,
    /// Taint CWE core (enables taint).
    Security,
    /// Bad practices only (advisory).
    Style,
    /// Full catalog.
    All,
}

impl ProfileArg {
    pub fn to_profile(self) -> ScanProfile {
        match self {
            Self::Recommended => ScanProfile::Recommended,
            Self::Perf => ScanProfile::Perf,
            Self::Security => ScanProfile::Security,
            Self::Style => ScanProfile::Style,
            Self::All => ScanProfile::All,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum RuleCategory {
    Security,
    Performance,
    BadPractice,
    General,
}

impl RuleCategory {
    pub fn as_category(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Performance => "performance",
            Self::BadPractice => "bad_practice",
            Self::General => "general",
        }
    }
}
