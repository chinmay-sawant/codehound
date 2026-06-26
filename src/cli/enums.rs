//! CLI enums: `Command`, `LangMode`, `OutputFormat`, `RuleCategory`.

use clap::{Subcommand, ValueEnum};

use crate::core::LanguageId;

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Write a starter `slopguard.toml` to the current directory.
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
