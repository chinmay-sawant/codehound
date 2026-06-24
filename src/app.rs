//! CLI orchestration for the `slopguard` binary.

use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use slopguard::cli::{Cli, Command, OutputFormat};
use slopguard::cwe::{RuleDescription, default_ruleset_path, load_rule_descriptions};
use slopguard::engine::{
    Analyzer, BASELINE_FILE_NAME, Baseline, CacheStore, DEFAULT_CACHE_DIR, Diagnostics, Registry,
    SlopguardConfig, TimingCollector, collect_entries, discover_baseline, discover_cache_dir,
    discover_config, resolve_language_filter,
};
use slopguard::export::export_findings;
use slopguard::reporting;

/// Conventional exit codes:
/// 0 — clean (no failing findings, no errors)
/// 1 — failing findings (per `FailPolicy`)
/// 2 — configuration error (unknown flag, invalid `slopguard.toml`, ...)
/// 3 — internal / I-O / engine error (scan aborted before completion)
pub const EXIT_CLEAN: u8 = 0;
pub const EXIT_FAILING: u8 = 1;
pub const EXIT_CONFIG: u8 = 2;
pub const EXIT_INTERNAL: u8 = 3;

pub fn run(cli: Cli) -> Result<ExitCode> {
    #[cfg(feature = "terminal-output")]
    {
        if cli.no_color || !colored::control::ShouldColorize::from_env().should_colorize() {
            colored::control::set_override(false);
        }
    }

    if let Some(Command::Init) = &cli.command {
        return Ok(init_subcommand());
    }

    if cli.list_rules {
        print_rules();
        return Ok(ExitCode::from(EXIT_CLEAN));
    }

    if let Some(rule_id) = &cli.explain {
        print_rule_explanation(rule_id);
        return Ok(ExitCode::from(EXIT_CLEAN));
    }

    let collect_stats = cli.debug_timing || cli.diagnostics.is_some();
    let mut app_timing = TimingCollector::new(collect_stats);

    let config = app_timing.measure("config_load", || load_config(cli.config.as_deref()))?;
    let registry = Registry::default();
    let lang_filter = resolve_language_filter(cli.lang.language_id(), config.as_ref(), &registry)?;

    let mut path_filters = config
        .as_ref()
        .map(|cfg| cfg.path_filters())
        .unwrap_or_default();
    if cli.include_tests {
        path_filters.exclude_tests = false;
    }

    let scan_context = cli.scan_context(config.clone());
    let collect_stats = scan_context.collect_stats();
    let analyzer = Analyzer::builder()
        .scan_context(scan_context)
        .path_filters(path_filters.clone())
        .language_filter(lang_filter.clone())
        .collect_stats(collect_stats)
        .build();

    let mut cache_store = open_cache_store(&cli, config.as_ref());
    if cli.rebuild_cache {
        if let Some(dir) = cache_rebuild_dir(&cli, config.as_ref()) {
            if dir.is_dir() {
                if let Err(e) = std::fs::remove_dir_all(&dir) {
                    if !cli.quiet {
                        eprintln!("warning: could not purge cache at {}: {e}", dir.display());
                    }
                } else if !cli.quiet {
                    eprintln!("Purged cache at {}", dir.display());
                }
            }
            // Re-open (or open for the first time) so the scan writes a
            // fresh cache instead of running with the store closed.
            cache_store = open_cache_store(&cli, config.as_ref());
        }
    }

    if cli.prune_cache {
        let (entries, _skipped) =
            collect_entries(&registry, &cli.paths, &lang_filter, &path_filters)?;
        let scanned_files: std::collections::HashSet<String> = entries
            .iter()
            .map(|e| e.path.display().to_string())
            .collect();
        if let Some(cache) = cache_store.as_mut() {
            let pruned = cache.prune(&scanned_files)?;
            let orphaned = cache.clean_orphans()?;
            cache.flush()?;
            if !cli.quiet {
                if pruned > 0 || orphaned > 0 {
                    eprintln!(
                        "Pruned {} stale manifest {} and removed {} orphaned cache {} from {}",
                        pruned,
                        if pruned == 1 { "entry" } else { "entries" },
                        orphaned,
                        if orphaned == 1 { "file" } else { "files" },
                        cache.cache_dir().display()
                    );
                } else {
                    eprintln!(
                        "Cache at {} is clean (0 stale entries, 0 orphans)",
                        cache.cache_dir().display()
                    );
                }
            }
        }
        return Ok(ExitCode::from(EXIT_CLEAN));
    }

    let mut result = match analyzer.analyze_paths(&cli.paths, cache_store.as_mut()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("internal error during scan: {e:#}");
            return Ok(ExitCode::from(EXIT_INTERNAL));
        }
    };

    if !result.errors.is_empty() {
        eprintln!("{} file(s) could not be scanned:", result.errors.len());
        for err in &result.errors {
            eprintln!("  - [{:?}] {}", err.kind, err);
        }
    }

    if cli.generate_baseline() {
        let baseline_path = cli
            .baseline_file
            .clone()
            .unwrap_or_else(|| Path::new(BASELINE_FILE_NAME).to_path_buf());
        let baseline = Baseline::from_findings(&result.findings);
        let entry_count = baseline.entry_count();
        baseline.to_file(&baseline_path)?;
        if !cli.quiet {
            println!(
                "Baseline saved with {entry_count} entr{} to {}",
                if entry_count == 1 { "y" } else { "ies" },
                baseline_path.display()
            );
        }
        return Ok(ExitCode::from(EXIT_CLEAN));
    }

    if baseline_loading_enabled(&cli, config.as_ref()) {
        if let Some(baseline_path) = baseline_load_path(&cli, config.as_ref()) {
            match Baseline::from_file(&baseline_path) {
                Ok(baseline) => {
                    if baseline.version != slopguard::engine::BASELINE_VERSION {
                        if !cli.quiet {
                            eprintln!(
                                "warning: skipping baseline {}: unsupported version {}",
                                baseline_path.display(),
                                baseline.version
                            );
                        }
                    } else {
                        if baseline.tool_version != env!("CARGO_PKG_VERSION") && !cli.quiet {
                            eprintln!(
                                "warning: baseline {} was generated by slopguard {}; current version is {}",
                                baseline_path.display(),
                                baseline.tool_version,
                                env!("CARGO_PKG_VERSION")
                            );
                        }
                        let before = result.findings.len();
                        result
                            .findings
                            .retain(|finding| !baseline.contains_finding(finding));
                        result.suppressed_count += before.saturating_sub(result.findings.len());
                        if !cli.quiet {
                            eprintln!(
                                "Using baseline with {} entr{} from {} (suppressed {})",
                                baseline.entry_count(),
                                if baseline.entry_count() == 1 {
                                    "y"
                                } else {
                                    "ies"
                                },
                                baseline_path.display(),
                                result.suppressed_count,
                            );
                        }
                    }
                }
                Err(err) => {
                    if !cli.quiet {
                        eprintln!(
                            "warning: could not load baseline {}: {err:#}",
                            baseline_path.display()
                        );
                    }
                }
            }
        }
    }

    let export_options = cli.export_options();
    let export_summary = app_timing.measure("export", || {
        export_findings(&result.findings, &export_options, &result.source_cache)
    })?;

    if !cli.no_terminal && !cli.quiet {
        app_timing.measure("reporting", || match cli.format {
            OutputFormat::Text => reporting::text::print_with_options(
                &result,
                reporting::text::TextOptions {
                    suppress_snippet: cli.no_snippet,
                    show_fingerprint: cli.show_fingerprint,
                    verbose: cli.verbose,
                    debug_timing: cli.debug_timing,
                },
            ),
            OutputFormat::Json if cli.json_envelope => reporting::json::print_envelope(&result),
            OutputFormat::Json => reporting::json::print(&result),
            OutputFormat::Sarif if cli.no_snippet => reporting::sarif::print_compact(&result),
            OutputFormat::Sarif => reporting::sarif::print(&result),
        })?;
    } else {
        let mut parts = Vec::new();
        if export_options.export_context {
            parts.push(format!(
                "Exported {} context file(s) to {}",
                export_summary.context_files_written,
                export_options.context_output_dir.display()
            ));
        }
        if export_options.export_chunks {
            parts.push(format!(
                "{} chunk file(s) to {}",
                export_summary.chunk_files_written,
                export_options.chunks_output_dir.display()
            ));
        }
        if !parts.is_empty() {
            println!("{}", parts.join(" and "));
        }
    }

    if collect_stats {
        if let Some(stats) = result.stats.as_mut() {
            let app_summary = app_timing.to_summary();
            if let Some(scan_timing) = stats.timing.as_mut() {
                scan_timing.merge(&app_summary);
            } else {
                stats.timing = Some(app_summary);
            }
        }
    }

    if let Some(diagnostics_path) = cli.diagnostics.as_ref() {
        if let Some(stats) = result.stats.as_ref() {
            let diagnostics = Diagnostics::from_stats(stats);
            let file = std::fs::File::create(diagnostics_path).with_context(|| {
                format!("creating diagnostics file {}", diagnostics_path.display())
            })?;
            serde_json::to_writer_pretty(file, &diagnostics).with_context(|| {
                format!("writing diagnostics file {}", diagnostics_path.display())
            })?;
        }
    }

    Ok(if !result.errors.is_empty() {
        ExitCode::from(EXIT_INTERNAL)
    } else if result.should_fail(analyzer.scan_context().fail_policy) {
        ExitCode::from(EXIT_FAILING)
    } else {
        ExitCode::from(EXIT_CLEAN)
    })
}

fn baseline_loading_enabled(cli: &Cli, config: Option<&SlopguardConfig>) -> bool {
    if cli.no_baseline {
        return false;
    }
    config.is_none_or(SlopguardConfig::baseline_enabled)
}

fn baseline_load_path(cli: &Cli, config: Option<&SlopguardConfig>) -> Option<std::path::PathBuf> {
    cli.baseline_file
        .clone()
        .or_else(|| config.and_then(SlopguardConfig::baseline_path))
        .or_else(|| discover_baseline(Path::new(".")))
}

pub fn load_config(explicit: Option<&Path>) -> Result<Option<SlopguardConfig>> {
    if let Some(path) = explicit {
        if !path.is_file() {
            anyhow::bail!("config file not found: {}", path.display());
        }
        Ok(Some(SlopguardConfig::load(path).with_context(|| {
            format!("loading config {}", path.display())
        })?))
    } else if let Some(found) = discover_config(Path::new(".")) {
        Ok(Some(SlopguardConfig::load(&found).with_context(|| {
            format!("loading config {}", found.display())
        })?))
    } else {
        Ok(None)
    }
}

pub fn print_rules() {
    let registry = Registry::default();
    let descriptions = load_descriptions();
    println!(
        "Registered rules ({} detectors, {} rules):",
        registry.detector_count(),
        registry
            .detectors()
            .iter()
            .map(|d| d.rule_ids().len())
            .sum::<usize>(),
    );
    for det in registry.detectors() {
        for id in det.rule_ids() {
            let title = descriptions
                .get(*id)
                .map(|d| d.name.as_str())
                .or_else(|| det.metadata_for(id).map(|m| m.title))
                .unwrap_or("<missing metadata>");
            println!("  {id:<12} {title}");
        }
    }
    if descriptions.is_empty() {
        eprintln!(
            "(rule descriptions not loaded from {}; install or build with ruleset)",
            default_ruleset_path().display()
        );
    }
}

pub fn print_rule_explanation(rule_id: &str) {
    let registry = Registry::default();
    for det in registry.detectors() {
        if det.rule_ids().contains(&rule_id) {
            let Some(m) = det.metadata_for(rule_id) else {
                continue;
            };
            println!("{} — {}", m.id, m.title);
            println!();
            println!("{}", m.description);
            if let Some(fix) = m.fix {
                println!();
                println!("Fix: {fix}");
            }
            let descriptions = load_descriptions();
            if let Some(rich) = descriptions.get(rule_id) {
                if rich.description != m.description {
                    println!();
                    println!("From the CWE catalog:");
                    println!("{}", rich.description);
                }
                if !rich.detection_notes.is_empty() {
                    println!();
                    println!("Detection notes:");
                    println!("{}", rich.detection_notes);
                }
            }
            return;
        }
    }
    eprintln!("unknown rule: {rule_id}");
}

fn load_descriptions() -> &'static HashMap<String, RuleDescription> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<HashMap<String, RuleDescription>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let path = default_ruleset_path();
        match load_rule_descriptions(&path) {
            Ok(map) => map,
            Err(e) => {
                eprintln!(
                    "warning: could not load rule descriptions from {}: {e}",
                    path.display()
                );
                HashMap::new()
            }
        }
    })
}

/// Resolve and open the incremental-analysis cache when enabled by
/// CLI flags + `slopguard.toml`. Returns `None` when the cache is
/// disabled (`--no-cache` or `cache.enabled = false`) or when the
/// directory cannot be opened.
fn open_cache_store(cli: &Cli, config: Option<&SlopguardConfig>) -> Option<CacheStore> {
    if cli.no_cache {
        return None;
    }
    if let Some(cfg) = config {
        if !cfg.cache_enabled() {
            return None;
        }
    }
    let dir = cache_directory(cli, config)?;
    let max_size_mb = config.map(|c| c.slopguard.cache.max_size_mb).unwrap_or(500);
    match CacheStore::open_with_capacity(dir, max_size_mb) {
        Ok(s) => Some(s),
        Err(e) => {
            if !cli.quiet {
                eprintln!("warning: could not open incremental cache: {e:#}");
            }
            None
        }
    }
}

/// Resolve the cache directory following CLI > config > auto-discovery
/// precedence. Returns `None` when none of the sources apply.
fn cache_directory(cli: &Cli, config: Option<&SlopguardConfig>) -> Option<std::path::PathBuf> {
    if let Some(dir) = cli.cache_dir.clone() {
        return Some(dir);
    }
    if let Some(cfg) = config {
        if let Some(p) = cfg.cache_path() {
            return Some(p);
        }
    }
    if let Some(found) = discover_cache_dir(Path::new(".")) {
        return Some(found);
    }
    // No existing cache: lazily create one in the cwd so the next run
    // can read it back.
    Some(Path::new(DEFAULT_CACHE_DIR).to_path_buf())
}

/// Directory that would be purged by `--rebuild-cache`. Mirrors
/// [`cache_directory`].
fn cache_rebuild_dir(cli: &Cli, config: Option<&SlopguardConfig>) -> Option<std::path::PathBuf> {
    cache_directory(cli, config)
}

pub fn init_subcommand() -> ExitCode {
    const TEMPLATE: &str = "\
# SlopGuard configuration. All fields are optional; unknown fields are rejected.
[slopguard]
# Limit analysis to specific languages.
# languages = [\"go\", \"python\"]

# Only run the union of these rule IDs and any passed via --only.
# only = [\"CWE-22\", \"CWE-89\"]

# Skip the union of these rule IDs and any passed via --skip.
# skip = [\"CWE-15\"]

# Exit policy: \"none\" | \"high\" | \"strict\" | anything else = warnings as errors.
# fail_on = \"high\"

# Optional include/exclude gitignore-style globs, relative to each scan root.
# include = [\"**/*.go\"]
# exclude = [\"**/vendor/**\", \"**/*_test.go\"]

# Test files (*_test.*) are excluded by default; set to false to include them.
# exclude_tests = false

# Baselines are enabled by default and auto-discovered upward from the current directory.
# [slopguard.baseline]
# enabled = true
# path = \".slopguard-baseline.json\"

# Bad-practice rules (BP-*) are enabled by default.
# [slopguard.bad_practices]
# enabled = true
# severity = \"low\"

# Incremental analysis cache is enabled by default. SlopGuard stores per-file
# results in `.slopguard-cache/` next to the project root and reuses them on
# subsequent runs when the file's content hash has not changed.
# [slopguard.cache]
# enabled = true
# path = \".slopguard-cache\"
";
    let path = Path::new("slopguard.toml");
    if path.is_file() {
        eprintln!("slopguard.toml already exists in this directory");
        return ExitCode::from(EXIT_CONFIG);
    }
    if let Err(e) = std::fs::write(path, TEMPLATE) {
        eprintln!("failed to write slopguard.toml: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }
    println!("wrote starter slopguard.toml to {}", path.display());
    ExitCode::from(EXIT_CLEAN)
}
