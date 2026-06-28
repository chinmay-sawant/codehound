use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use slopguard::cli::{Cli, Command, OutputFormat};
use slopguard::engine::{
    AnalysisResult, Analyzer, BASELINE_FILE_NAME, Baseline, CacheStore, Diagnostics,
    LanguageFilter, PathFilters, Registry, SlopguardConfig, TimingCollector, collect_entries,
    resolve_language_filter,
};
use slopguard::export::{ExportOptions, ExportSummary, export_findings};
use slopguard::reporting;

use super::cache::{cache_directory, open_cache_store};
use super::config::{baseline_load_path, baseline_loading_enabled, load_config};
use super::exit_codes::{EXIT_CLEAN, EXIT_FAILING, EXIT_INTERNAL};
use super::init_cmd::init_subcommand;
use super::rule_info::{print_rule_explanation, print_rules};

pub fn run(cli: Cli) -> Result<ExitCode> {
    configure_terminal_color(&cli);

    if let Some(Command::Init) = &cli.command {
        return Ok(init_subcommand());
    }

    if cli.list_rules {
        return run_list_rules(cli);
    }

    if let Some(rule_id) = &cli.explain {
        return run_explain(rule_id);
    }

    run_scan(cli)
}

fn configure_terminal_color(cli: &Cli) {
    #[cfg(feature = "terminal-output")]
    {
        if cli.no_color || !colored::control::ShouldColorize::from_env().should_colorize() {
            colored::control::set_override(false);
        }
    }
}

fn run_list_rules(cli: Cli) -> Result<ExitCode> {
    print_rules(cli.rule_category);
    Ok(ExitCode::from(EXIT_CLEAN))
}

fn run_explain(rule_id: &str) -> Result<ExitCode> {
    print_rule_explanation(rule_id);
    Ok(ExitCode::from(EXIT_CLEAN))
}

fn run_scan(cli: Cli) -> Result<ExitCode> {
    let collect_stats = cli.debug_timing || cli.diagnostics.is_some();
    let mut app_timing = TimingCollector::new(collect_stats);

    let config = app_timing.measure("config_load", || load_config(cli.config.as_deref()))?;
    let registry = Registry::default();
    let lang_filter = resolve_language_filter(cli.lang.language_id(), config.as_ref(), &registry)?;

    let mut path_filters = config
        .as_ref()
        .map(|cfg| {
            use slopguard::engine::PathFilters;
            PathFilters {
                include: cfg.slopguard.include.clone(),
                exclude: cfg.slopguard.exclude.clone(),
                exclude_tests: cfg.slopguard.exclude_tests.unwrap_or(true),
            }
        })
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
    rebuild_cache_if_requested(&cli, config.as_ref(), &mut cache_store);

    if cli.prune_cache {
        return run_prune_cache(&cli, &registry, &lang_filter, &path_filters, cache_store);
    }

    let mut result = match analyzer.analyze_paths(&cli.paths, cache_store.as_mut()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("internal error during scan: {e:#}");
            return Ok(ExitCode::from(EXIT_INTERNAL));
        }
    };

    report_scan_errors(&result);

    if cli.baseline {
        return save_baseline(&cli, &result);
    }

    apply_baseline_filter(&cli, config.as_ref(), &mut result);

    let export_options = cli.export_options();
    let export_summary = app_timing.measure("export", || {
        export_findings(&result.findings, &export_options, &result.source_cache)
    })?;

    emit_output(
        &cli,
        &mut app_timing,
        &result,
        &export_options,
        &export_summary,
    )?;
    merge_app_timing(&mut result, &app_timing, collect_stats);
    write_diagnostics(&cli, &result)?;

    Ok(scan_exit_code(&result, analyzer.ctx.fail_policy))
}

fn rebuild_cache_if_requested(
    cli: &Cli,
    config: Option<&SlopguardConfig>,
    cache_store: &mut Option<CacheStore>,
) {
    if !cli.rebuild_cache {
        return;
    }
    let Some(dir) = cache_directory(cli, config) else {
        return;
    };
    if !dir.is_dir() {
        return;
    }
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        if !cli.quiet {
            eprintln!("warning: could not purge cache at {}: {e}", dir.display());
        }
    } else if !cli.quiet {
        eprintln!("Purged cache at {}", dir.display());
    }
    *cache_store = open_cache_store(cli, config);
}

fn run_prune_cache(
    cli: &Cli,
    registry: &Registry,
    lang_filter: &LanguageFilter,
    path_filters: &PathFilters,
    mut cache_store: Option<CacheStore>,
) -> Result<ExitCode> {
    let (entries, _skipped) = collect_entries(registry, &cli.paths, lang_filter, path_filters)?;
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
    Ok(ExitCode::from(EXIT_CLEAN))
}

fn report_scan_errors(result: &AnalysisResult) {
    if result.errors.is_empty() {
        return;
    }
    eprintln!("{} file(s) could not be scanned:", result.errors.len());
    for err in &result.errors {
        eprintln!("  - [{:?}] {}", err.kind, err);
    }
}

fn save_baseline(cli: &Cli, result: &AnalysisResult) -> Result<ExitCode> {
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
    Ok(ExitCode::from(EXIT_CLEAN))
}

fn apply_baseline_filter(cli: &Cli, config: Option<&SlopguardConfig>, result: &mut AnalysisResult) {
    if !baseline_loading_enabled(cli, config) {
        return;
    }
    let Some(baseline_path) = baseline_load_path(cli, config) else {
        return;
    };
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
                return;
            }
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
        Err(err) if !cli.quiet => {
            eprintln!(
                "warning: could not load baseline {}: {err:#}",
                baseline_path.display()
            );
        }
        _ => {}
    }
}

fn emit_output(
    cli: &Cli,
    app_timing: &mut TimingCollector,
    result: &AnalysisResult,
    export_options: &ExportOptions,
    export_summary: &ExportSummary,
) -> Result<()> {
    if !cli.no_terminal && !cli.quiet {
        app_timing.measure("reporting", || match cli.format {
            OutputFormat::Text => reporting::text::print_with_options(
                result,
                reporting::text::TextOptions {
                    suppress_snippet: cli.no_snippet,
                    show_fingerprint: cli.show_fingerprint,
                    verbose: cli.verbose,
                    debug_timing: cli.debug_timing,
                },
            ),
            OutputFormat::Json if cli.json_envelope => reporting::json::print_envelope(result),
            OutputFormat::Json => reporting::json::print(result),
            OutputFormat::Sarif if cli.no_snippet => reporting::sarif::print_compact(result),
            OutputFormat::Sarif => reporting::sarif::print(result),
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
    Ok(())
}

fn merge_app_timing(
    result: &mut AnalysisResult,
    app_timing: &TimingCollector,
    collect_stats: bool,
) {
    if !collect_stats {
        return;
    }
    if let Some(stats) = result.stats.as_mut() {
        let app_summary = app_timing.to_summary();
        if let Some(scan_timing) = stats.timing.as_mut() {
            scan_timing.merge(&app_summary);
        } else {
            stats.timing = Some(app_summary);
        }
    }
}

fn write_diagnostics(cli: &Cli, result: &AnalysisResult) -> Result<()> {
    let Some(diagnostics_path) = cli.diagnostics.as_ref() else {
        return Ok(());
    };
    let Some(stats) = result.stats.as_ref() else {
        return Ok(());
    };
    let diagnostics = Diagnostics::from_stats(stats);
    let file = std::fs::File::create(diagnostics_path)
        .with_context(|| format!("creating diagnostics file {}", diagnostics_path.display()))?;
    serde_json::to_writer_pretty(file, &diagnostics)
        .with_context(|| format!("writing diagnostics file {}", diagnostics_path.display()))?;
    Ok(())
}

fn scan_exit_code(result: &AnalysisResult, fail_policy: slopguard::core::FailPolicy) -> ExitCode {
    if !result.errors.is_empty() {
        let code = result
            .errors
            .iter()
            .map(|e| e.kind.exit_code())
            .max()
            .unwrap_or(EXIT_INTERNAL);
        ExitCode::from(code)
    } else if result.should_fail(fail_policy) {
        ExitCode::from(EXIT_FAILING)
    } else {
        ExitCode::from(EXIT_CLEAN)
    }
}
