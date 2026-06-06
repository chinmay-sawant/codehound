//! CLI orchestration for the `slopguard` binary.

use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use slopguard::cli::{Cli, Command, OutputFormat};
use slopguard::cwe::{RuleDescription, default_ruleset_path, load_rule_descriptions};
use slopguard::engine::{
    Analyzer, Registry, SlopguardConfig, discover_config, resolve_language_filter,
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
    if cli.no_color || !colored::control::ShouldColorize::from_env().should_colorize() {
        colored::control::set_override(false);
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

    let config = load_config(cli.config.as_deref())?;
    let registry = Registry::default();
    let lang_filter = resolve_language_filter(cli.lang.language_id(), config.as_ref(), &registry)?;

    let mut path_filters = config
        .as_ref()
        .map(|cfg| cfg.path_filters())
        .unwrap_or_default();
    if cli.exclude_tests {
        path_filters.exclude_tests = true;
    }

    let analyzer = Analyzer::builder()
        .scan_context(cli.scan_context(config.clone()))
        .path_filters(path_filters)
        .language_filter(lang_filter)
        .build();

    let result = match analyzer.analyze_paths(&cli.paths) {
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

    let export_options = cli.export_options();
    let export_summary = export_findings(&result.findings, &export_options)?;

    if !cli.no_terminal && !cli.quiet {
        match cli.format {
            OutputFormat::Text if cli.no_snippet => {
                reporting::text::print_without_snippet(&result)?
            }
            OutputFormat::Text => reporting::text::print(&result)?,
            OutputFormat::Json if cli.json_envelope => reporting::json::print_envelope(&result)?,
            OutputFormat::Json => reporting::json::print(&result)?,
            OutputFormat::Sarif if cli.no_snippet => reporting::sarif::print_compact(&result)?,
            OutputFormat::Sarif => reporting::sarif::print(&result)?,
        }
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

    Ok(if result.should_fail(analyzer.scan_context().fail_policy) {
        ExitCode::from(EXIT_FAILING)
    } else {
        ExitCode::from(EXIT_CLEAN)
    })
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

# Exclude all test files (*_test.*) — simpler than the glob above.
# exclude_tests = true
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
