//! CLI enums: `Command`, `LangMode`, `OutputFormat`, `RuleCategory`, `ProfileArg`.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use crate::core::{LanguageId, ScanProfile};

/// Top-level CLI subcommands.
#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Write a starter `codehound.toml` to the current directory.
    Init,
    /// List rules or explain a rule id.
    Rules {
        /// Filter by category.
        #[arg(long, value_enum)]
        category: Option<RuleCategory>,
        /// Explain a single rule id.
        #[arg(long, value_name = "RULE")]
        explain: Option<String>,
    },
    /// Incremental analysis cache operations.
    Cache {
        /// Cache subcommand to run.
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Baseline management for brownfield adoption.
    Baseline {
        /// Baseline subcommand to run.
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Explicit scan (same defaults as bare `codehound [PATHS…]`).
    Scan {
        /// Paths to analyze.
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
    },
}

/// Subcommands for `codehound cache`.
#[derive(Debug, Clone, Subcommand)]
pub enum CacheAction {
    /// Remove stale entries for files no longer on disk, then exit.
    Prune,
}

/// Subcommands for `codehound baseline`.
#[derive(Debug, Clone, Subcommand)]
pub enum BaselineAction {
    /// List baselined entries.
    List {
        /// Baseline file path (default: discover `.codehound-baseline.json`).
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Drop baselined fingerprints not present in a fresh scan of PATHS.
    Prune {
        /// Paths to scan when deciding which baseline entries are still live.
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
        /// Baseline file path (default: discover `.codehound-baseline.json`).
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Merge current findings into the baseline (add/update).
    Update {
        /// Paths to scan for findings to merge into the baseline.
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
        /// Baseline file path (default: discover `.codehound-baseline.json`).
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Diff live findings vs baseline (new vs stale).
    Diff {
        /// Paths to scan for the live side of the baseline diff.
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
        /// Baseline file path (default: discover `.codehound-baseline.json`).
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Save current findings as the baseline (alias of `--baseline`).
    Save {
        /// Paths to scan for findings written into a new baseline.
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
        /// Baseline file path (default: discover `.codehound-baseline.json`).
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
}

/// Language selection for path discovery and parsing.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum LangMode {
    /// Infer language from file extension.
    #[default]
    Auto,
    /// Force Go analysis only.
    Go,
    /// Force Python analysis only (requires the `python` feature).
    Python,
}

impl LangMode {
    /// Map to a concrete [`LanguageId`], or `None` for auto-detection.
    pub fn language_id(self) -> Option<LanguageId> {
        match self {
            LangMode::Auto => None,
            LangMode::Go => Some(LanguageId::Go),
            LangMode::Python => Some(LanguageId::Python),
        }
    }
}

/// Reporter output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text (default).
    #[default]
    Text,
    /// Machine-readable JSON envelope.
    Json,
    /// SARIF 2.1.0 for CI integrations.
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
    /// Convert CLI profile to the engine [`ScanProfile`].
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

/// High-level rule category filter for `--list-rules` / `rules`.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum RuleCategory {
    /// Security / CWE-oriented rules.
    Security,
    /// Performance heuristics.
    Performance,
    /// Bad-practice / style pack.
    BadPractice,
    /// Catch-all for uncategorized rules.
    General,
}

impl RuleCategory {
    /// Stable string used in rule metadata / filtering.
    pub fn as_category(self) -> &'static str {
        match self {
            Self::Security => "security",
            Self::Performance => "performance",
            Self::BadPractice => "bad_practice",
            Self::General => "general",
        }
    }
}
