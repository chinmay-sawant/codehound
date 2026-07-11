//! CLI enums: `Command`, `LangMode`, `OutputFormat`, `RuleCategory`, `ProfileArg`.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

use crate::core::{LanguageId, ScanProfile};

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
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Baseline management for brownfield adoption.
    Baseline {
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

#[derive(Debug, Clone, Subcommand)]
pub enum CacheAction {
    /// Remove stale entries for files no longer on disk, then exit.
    Prune,
}

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
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Merge current findings into the baseline (add/update).
    Update {
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Diff live findings vs baseline (new vs stale).
    Diff {
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Save current findings as the baseline (alias of `--baseline`).
    Save {
        #[arg(value_name = "PATH", default_values = ["."])]
        paths: Vec<String>,
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
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
