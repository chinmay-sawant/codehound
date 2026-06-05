//! Command-line argument definitions.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::core::{FailPolicy, LanguageId, ScanContext};
use crate::engine::build_scan_context;
use crate::export::ExportOptions;

/// SlopGuard — static analyzer for performance slop in multiple languages.
#[derive(Debug, Parser)]
#[command(
    name = "slopguard",
    version,
    about = "Detect performance bottlenecks and slop (Go, Python, …) in source code",
    long_about = None,
    styles = clap::builder::Styles::styled(),
    after_help = "EXAMPLES:\n  \
        slopguard                            # scan the current directory\n  \
        slopguard ./cmd/foo.go               # scan a single file\n  \
        slopguard --only CWE-22,CWE-89       # only the named rules\n  \
        slopguard --format sarif > out.sarif # SARIF for CI\n  \
        slopguard --list-rules               # show every registered rule\n  \
        slopguard --explain CWE-89           # details for a specific rule\n  \
        slopguard init                       # write a starter slopguard.toml"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Paths to analyze (files or directories).
    #[arg(value_name = "PATH", default_values = ["."])]
    pub paths: Vec<String>,

    /// Language filter: auto-detect from extension, or force a language.
    #[arg(long, value_enum, default_value_t = LangMode::Auto)]
    pub lang: LangMode,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Path to a `slopguard.toml` (overrides auto-discovery).
    #[arg(long, env = "SLOPGUARD_CONFIG")]
    pub config: Option<PathBuf>,

    /// Only run the given rule IDs (comma-separated).
    #[arg(long, value_delimiter = ',', env = "SLOPGUARD_ONLY")]
    pub only: Vec<String>,

    /// Skip the given rule IDs (comma-separated).
    #[arg(long, value_delimiter = ',', env = "SLOPGUARD_SKIP")]
    pub skip: Vec<String>,

    /// Exit policy for findings.
    #[command(flatten)]
    pub severity: SeverityArgs,

    /// Verbosity: 0 = default, 1 = info, 2 = debug.
    #[arg(long, value_name = "LEVEL", default_value_t = 0, global = true)]
    pub verbose: u8,

    /// Suppress all output except errors.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Disable colored output.
    #[arg(long, env = "NO_COLOR")]
    pub no_color: bool,

    /// Do not print findings to stdout.
    #[arg(long)]
    pub no_terminal: bool,

    /// Do not write per-finding context files.
    #[arg(long)]
    pub no_context: bool,

    /// Do not write chunk files.
    #[arg(long)]
    pub no_chunks: bool,

    /// Suppress the source snippet in text output.
    #[arg(long)]
    pub no_snippet: bool,

    /// Number of findings per chunk file.
    #[arg(long, default_value_t = 25)]
    pub chunk_size: usize,

    /// Directory for numbered finding context files.
    #[arg(long, default_value = "scripts/findings/functions")]
    pub context_output_dir: PathBuf,

    /// Directory for chunk files.
    #[arg(long, default_value = "scripts/chunks")]
    pub chunks_output_dir: PathBuf,

    /// List all registered rules and exit.
    #[arg(long)]
    pub list_rules: bool,

    /// Show details for a specific rule ID and exit.
    #[arg(long, value_name = "RULE")]
    pub explain: Option<String>,
}

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

    /// True iff the user explicitly chose a severity policy on the CLI.
    pub fn is_explicit(self) -> bool {
        self.no_fail || self.strict || self.warnings_as_errors
    }
}

impl Cli {
    pub fn scan_context(&self, config: Option<crate::engine::SlopguardConfig>) -> ScanContext {
        let cli_set_fail_policy = self.severity.is_explicit();
        build_scan_context(
            self.only.clone(),
            self.skip.clone(),
            self.severity.fail_policy(),
            config,
            cli_set_fail_policy,
        )
    }

    pub fn export_options(&self) -> ExportOptions {
        ExportOptions {
            export_context: !self.no_context,
            export_chunks: !self.no_chunks,
            chunk_size: self.chunk_size,
            context_output_dir: self.context_output_dir.clone(),
            chunks_output_dir: self.chunks_output_dir.clone(),
        }
    }
}
