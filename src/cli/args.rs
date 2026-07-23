//! `Cli` struct (clap field list).

use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "codehound",
    version,
    about = "Detect performance bottlenecks and slop (Go, Python, …) in source code",
    long_about = None,
    styles = clap::builder::Styles::styled(),
    after_help = "EXAMPLES:\n  \
        codehound                            # scan the current directory\n  \
        codehound ./cmd/foo.go               # scan a single file\n  \
        codehound --only CWE-22,CWE-89       # only the named rules\n  \
        codehound --format sarif > out.sarif # SARIF for CI\n  \
        codehound --profile recommended .    # default high-signal CI pack\n  \
        codehound --profile security --taint # taint CWE core (taint on with security)\n  \
        codehound --profile all              # full catalog\n  \
        codehound --export-context --export-chunks  # opt-in filesystem export\n  \
        codehound --taint                    # enable experimental taint tracking\n  \
        codehound --typed                    # optional Go package facts (needs go toolchain)\n  \
        codehound --taint-show-paths         # emit taint-path evidence\n  \
        codehound --diagnostics-summary      # compact scan stats\n  \
        codehound --list-rules               # show every registered rule\n  \
        codehound rules --explain CWE-89     # maturity, packs, quarantine, docs\n  \
        codehound --explain CWE-334          # fixture-only: --profile all only\n  \
        codehound init                       # write a starter codehound.toml"
)]
/// Top-level command-line interface for the `codehound` binary.
pub struct Cli {
    /// Optional subcommand (`init`, `rules`, `cache`, `baseline`, `scan`).
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

    /// Product pack: recommended (default CI), perf, security, style, all.
    #[arg(long, value_enum, default_value_t = super::enums::ProfileArg::Recommended, env = "CODEHOUND_PROFILE")]
    pub profile: super::enums::ProfileArg,

    /// Path to a `codehound.toml` (overrides auto-discovery).
    #[arg(long, env = "CODEHOUND_CONFIG")]
    pub config: Option<PathBuf>,

    /// Only run the given rule IDs (comma-separated).
    #[arg(long, value_delimiter = ',', env = "CODEHOUND_ONLY")]
    pub only: Vec<String>,

    /// Skip the given rule IDs (comma-separated).
    #[arg(long, value_delimiter = ',', env = "CODEHOUND_SKIP")]
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

    /// Enable optional Go package-graph facts via `go list` (G4). Requires a Go
    /// toolchain; degrades to tree-sitter-only if unavailable. Never required
    /// for recommended/default scans.
    #[arg(long)]
    pub typed: bool,

    /// Disable typed package facts even if config enables them.
    #[arg(long)]
    pub no_typed: bool,

    /// Emit taint-path evidence in finding output (JSON/SARIF/text).
    #[arg(long)]
    pub taint_show_paths: bool,

    /// Inter-procedural taint summary hops (1 = direct only; max 4).
    #[arg(long, value_name = "N", default_value_t = 1)]
    pub taint_depth: u32,

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

    /// Write per-finding context files (default: off — opt-in only).
    #[arg(long)]
    pub export_context: bool,

    /// Write chunk files (default: off — opt-in only).
    #[arg(long)]
    pub export_chunks: bool,

    /// Deprecated alias: context export is off by default.
    #[arg(long, hide = true)]
    pub no_context: bool,

    /// Deprecated alias: chunk export is off by default.
    #[arg(long, hide = true)]
    pub no_chunks: bool,

    /// Suppress the source snippet in text output.
    #[arg(long)]
    pub no_snippet: bool,

    /// Emit compact SARIF (omit optional verbose fields). Independent of `--no-snippet`.
    #[arg(long)]
    pub sarif_compact: bool,

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
    #[arg(long, conflicts_with = "no_baseline")]
    pub baseline: bool,

    /// Ignore any existing `.codehound-baseline.json` file.
    #[arg(long, conflicts_with = "baseline")]
    pub no_baseline: bool,

    /// Report findings suppressed by codehound-ignore comments.
    #[arg(long)]
    pub show_ignored: bool,

    /// Report findings suppressed by the baseline (mirror `--show-ignored`).
    #[arg(long)]
    pub show_baselined: bool,

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

    /// Exclude example/demo paths from discovery
    /// (`**/examples/**`, `**/example/**`, `**/sampledata/**`, `**/samples/**`).
    /// Default still scans examples and labels those findings with the `example` tag.
    #[arg(long)]
    pub exclude_examples: bool,

    /// Disable the incremental analysis cache for this run.
    #[arg(long)]
    pub no_cache: bool,

    /// Custom directory for the incremental analysis cache
    /// (overrides `cache.path` in `codehound.toml`).
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
