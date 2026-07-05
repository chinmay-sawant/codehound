//! `Cli` struct (clap field list).

use std::path::PathBuf;

use clap::Parser;

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
        slopguard --taint                    # enable experimental taint tracking\n  \
        slopguard --taint-show-paths         # emit taint-path evidence\n  \
        slopguard --diagnostics-summary      # compact scan stats\n  \
        slopguard --list-rules               # show every registered rule\n  \
        slopguard --explain CWE-89           # details for a specific rule\n  \
        slopguard init                       # write a starter slopguard.toml"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<super::enums::Command>,

    /// Paths to analyze (files or directories).
    #[arg(value_name = "PATH", default_values = ["."])]
    pub paths: Vec<String>,

    /// Language filter: auto-detect from extension, or force a language.
    #[arg(long, value_enum, default_value_t = super::enums::LangMode::Auto)]
    pub lang: super::enums::LangMode,

    /// Output format.
    #[arg(long, value_enum, default_value_t = super::enums::OutputFormat::Text)]
    pub format: super::enums::OutputFormat,

    /// Path to a `slopguard.toml` (overrides auto-discovery).
    #[arg(long, env = "SLOPGUARD_CONFIG")]
    pub config: Option<PathBuf>,

    /// Only run the given rule IDs (comma-separated).
    #[arg(long, value_delimiter = ',', env = "SLOPGUARD_ONLY")]
    pub only: Vec<String>,

    /// Skip the given rule IDs (comma-separated).
    #[arg(long, value_delimiter = ',', env = "SLOPGUARD_SKIP")]
    pub skip: Vec<String>,

    /// Only run bad-practice rules (`BP-*`).
    #[arg(long)]
    pub bp_only: bool,

    /// Disable all bad-practice rules (`BP-*`).
    #[arg(long)]
    pub no_bp: bool,

    /// Enable experimental taint-tracking engine for CWE-22/78/79/89.
    #[arg(long)]
    pub taint: bool,

    /// Disable taint tracking even if config enables it.
    #[arg(long)]
    pub no_taint: bool,

    /// Emit taint-path evidence in finding output (JSON/SARIF/text).
    #[arg(long)]
    pub taint_show_paths: bool,

    /// Exit policy for findings.
    #[command(flatten)]
    pub severity: super::severity_args::SeverityArgs,

    /// Suppress all output except errors.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Disable colored output (honors `NO_COLOR=1` and similar truthy env values).
    #[arg(
        long,
        env = "NO_COLOR",
        action = clap::ArgAction::Set,
        value_parser = clap::builder::BoolishValueParser::new(),
        default_value = "false",
        hide_env_values = true,
    )]
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

    /// Show canonical finding fingerprints in text output.
    #[arg(long)]
    pub show_fingerprint: bool,

    /// Show extra detector details in text output.
    #[arg(long)]
    pub verbose: bool,

    /// Print per-detector timing after findings.
    #[arg(long)]
    pub debug_timing: bool,

    /// Write machine-readable scan diagnostics to FILE.
    #[arg(long, value_name = "FILE")]
    pub diagnostics: Option<PathBuf>,

    /// Print a compact scan summary (files scanned, cache hits/misses,
    /// slowest detector, total time) to stderr. Works with both scan
    /// and --list-rules.
    #[arg(long)]
    pub diagnostics_summary: bool,

    /// Number of findings per chunk file.
    #[arg(long, default_value_t = 25)]
    pub chunk_size: usize,

    /// Directory for numbered finding context files.
    #[arg(long, default_value = "scripts/findings/functions")]
    pub context_output_dir: PathBuf,

    /// Directory for chunk files.
    #[arg(long, default_value = "scripts/chunks")]
    pub chunks_output_dir: PathBuf,

    /// Emit JSON as a single envelope object (not NDJSON).
    #[arg(long)]
    pub json_envelope: bool,

    /// Save current findings as the baseline and exit.
    #[arg(long)]
    pub baseline: bool,

    /// Ignore any existing `.slopguard-baseline.json` file.
    #[arg(long)]
    pub no_baseline: bool,

    /// Report findings suppressed by slopguard-ignore comments.
    #[arg(long)]
    pub show_ignored: bool,

    /// Path to a custom baseline file.
    #[arg(long, value_name = "PATH")]
    pub baseline_file: Option<PathBuf>,

    /// List all registered rules and exit.
    #[arg(long)]
    pub list_rules: bool,

    /// Filter --list-rules output by rule category.
    #[arg(long, value_enum)]
    pub rule_category: Option<super::enums::RuleCategory>,

    /// Include test files (*_test.*) in analysis (excluded by default).
    #[arg(long)]
    pub include_tests: bool,

    /// Disable the incremental analysis cache for this run.
    #[arg(long)]
    pub no_cache: bool,

    /// Custom directory for the incremental analysis cache
    /// (overrides `cache.path` in `slopguard.toml`).
    #[arg(long, value_name = "DIR")]
    pub cache_dir: Option<PathBuf>,

    /// Purge the existing incremental cache and start fresh.
    #[arg(long)]
    pub rebuild_cache: bool,

    /// Remove stale cache entries for files that no longer exist,
    /// then exit without scanning.
    #[arg(long)]
    pub prune_cache: bool,

    /// Show details for a specific rule ID and exit.
    #[arg(long, value_name = "RULE")]
    pub explain: Option<String>,
}
