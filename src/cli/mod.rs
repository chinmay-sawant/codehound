//! Command-line argument definitions.

use clap::{Args, Parser, ValueEnum};

use crate::core::{FailPolicy, LanguageId, ScanContext};
use crate::engine::build_scan_context;

/// SlopGuard — static analyzer for performance slop in multiple languages.
#[derive(Debug, Parser)]
#[command(
    name = "slopguard",
    version,
    about = "Detect performance bottlenecks and slop (Go, Python, …) in source code",
    long_about = None,
    styles = clap::builder::Styles::styled(),
)]
pub struct Cli {
    /// Paths to analyze (files or directories).
    #[arg(value_name = "PATH", default_values = ["."])]
    pub paths: Vec<String>,

    /// Language filter: auto-detect from extension, or force a language.
    #[arg(long, value_enum, default_value_t = LangMode::Auto)]
    pub lang: LangMode,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Only run the given rule IDs (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,

    /// Skip the given rule IDs (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub skip: Vec<String>,

    /// Exit policy for findings.
    #[command(flatten)]
    pub severity: SeverityArgs,

    /// Disable colored output.
    #[arg(long)]
    pub no_color: bool,
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

#[derive(Debug, Clone, Copy, Args)]
#[group(multiple = false)]
pub struct SeverityArgs {
    /// Exit non-zero on warnings (default).
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
            FailPolicy::WarningsAsErrors
        }
    }
}

impl Cli {
    pub fn scan_context(&self) -> ScanContext {
        build_scan_context(
            self.only.clone(),
            self.skip.clone(),
            self.severity.fail_policy(),
        )
    }
}
