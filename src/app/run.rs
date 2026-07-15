use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use codehound::cli::{CacheAction, Cli, Command, OutputFormat};
use codehound::engine::{
    AnalysisResult, Analyzer, BASELINE_FILE_NAME, Baseline, CacheSession, CacheStore,
    CodehoundConfig, DEFAULT_CACHE_DIR, Diagnostics, FilesystemWalker, LanguageFilter, PathFilters,
    Registry, RunConfigParams, ScanContextParams, TimingCollector, build_run_config,
    collect_entries_with, resolve_language_filter,
};
use codehound::export::{ExportOptions, ExportSummary, export_findings};
use codehound::fixture::{FIXTURE_EXTENSION, materialize_fixture, parse_fixture};
use codehound::reporting;

use super::baseline_cmd::run_baseline_command;
use super::cache::{cache_directory, open_cache_store};
use super::config::{baseline_load_path, baseline_loading_enabled, load_config};
use super::exit_codes::{EXIT_CLEAN, EXIT_FAILING, EXIT_INTERNAL};
use super::init_cmd::init_subcommand;
use super::rule_info::{print_rule_explanation, print_rules};

pub fn run(mut cli: Cli) -> Result<ExitCode> {
    configure_terminal_color(&cli);

    // Take subcommand ownership first so we can move `cli` into handlers.
    let command = cli.command.take();
    match command {
        Some(Command::Init) => return Ok(init_subcommand()),
        Some(Command::Rules { category, explain }) => {
            if let Some(rule_id) = explain {
                return run_explain(&rule_id);
            }
            print_rules(category);
            return Ok(ExitCode::from(EXIT_CLEAN));
        }
        Some(Command::Cache {
            action: CacheAction::Prune,
        }) => {
            cli.prune_cache = true;
            return run_scan(cli);
        }
        Some(Command::Baseline { action }) => {
            return run_baseline_command(&cli, &action);
        }
        Some(Command::Scan { paths }) => {
            if !paths.is_empty() {
                cli.paths = paths;
            }
            return run_scan(cli);
        }
        None => {}
    }

    if cli.list_rules {
        return run_list_rules(cli);
    }

    if let Some(rule_id) = &cli.explain {
        return run_explain(rule_id);
    }

    run_scan(cli)
}

fn export_options_for_run(cli: &Cli) -> ExportOptions {
    // Export is off by default; require explicit --export-context / --export-chunks.
    // --no-context / --no-chunks remain accepted as no-ops for older scripts.
    ExportOptions {
        export_context: cli.export_context,
        export_chunks: cli.export_chunks,
        chunk_size: cli.chunk_size,
        context_output_dir: cli.context_output_dir.clone(),
        chunks_output_dir: cli.chunks_output_dir.clone(),
    }
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

/// CLI scan orchestration behind a single interface.
struct ScanRun {
    cli: Cli,
}

impl ScanRun {
    fn new(cli: Cli) -> Self {
        Self { cli }
    }

    fn execute(self) -> Result<ExitCode> {
        let cli = self.cli;
        let config = load_config(cli.config.as_deref())?;
        let registry = Registry::default();
        let lang_filter =
            resolve_language_filter(cli.lang.language_id(), config.as_ref(), &registry)?;

        let run_config = build_run_config(RunConfigParams {
            scan: scan_context_params_for_run(&cli, config.clone()),
            include_tests: cli.include_tests,
        });
        let collect_stats = run_config.scan_context.collect_stats();
        let mut app_timing = TimingCollector::new(collect_stats);
        let analyzer = Analyzer::builder()
            .scan_context(run_config.scan_context.clone())
            .path_filters(run_config.path_filters.clone())
            .language_filter(lang_filter.clone())
            .collect_stats(collect_stats)
            .build();

        let mut cache_store = open_cache_store(&cli, config.as_ref());
        if let Some(store) = cache_store.as_mut() {
            store.ensure_rule_config_hash(&run_config.scan_context.rule_config_fingerprint());
        }
        rebuild_cache_if_requested(&cli, config.as_ref(), &mut cache_store);

        if cli.prune_cache {
            return run_prune_cache(
                &cli,
                &registry,
                &lang_filter,
                &run_config.path_filters,
                cache_store,
            );
        }

        let scan_paths = resolve_scan_paths(&cli.paths)?;
        let mut result = analyzer.analyze_paths(
            &scan_paths,
            CacheSession::from_optional(cache_store.as_mut()),
        )?;

        report_scan_errors(&result);

        if cli.baseline {
            return save_baseline(&cli, &result);
        }

        apply_baseline_filter(&cli, config.as_ref(), &mut result);

        let export_options = export_options_for_run(&cli);
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
        write_diagnostics_summary(&cli, &result);

        Ok(scan_exit_code(&result, analyzer.ctx.fail_policy))
    }
}

fn run_scan(cli: Cli) -> Result<ExitCode> {
    ScanRun::new(cli).execute()
}

pub(crate) fn scan_context_params_for_run(
    cli: &Cli,
    config: Option<CodehoundConfig>,
) -> ScanContextParams {
    ScanContextParams {
        only: cli.only.clone(),
        skip: cli.skip.clone(),
        fail_policy: cli.severity.fail_policy(),
        config,
        cli_set_fail_policy: cli.severity.is_explicit(),
        debug_timing: cli.debug_timing,
        diagnostics: cli.diagnostics.is_some(),
        diagnostics_summary: cli.diagnostics_summary,
        verbose: cli.verbose,
        bp_only: cli.bp_only,
        no_bp: cli.no_bp,
        taint: cli.taint,
        no_taint: cli.no_taint,
        taint_show_paths: cli.taint_show_paths,
        taint_depth: cli.taint_depth,
        show_ignored: cli.show_ignored,
        profile: cli.profile.to_profile(),
        // Only pay the monorepo source_cache cost when export needs it.
        retain_sources: cli.export_context || cli.export_chunks,
    }
}

fn rebuild_cache_if_requested(
    cli: &Cli,
    config: Option<&CodehoundConfig>,
    cache_store: &mut Option<CacheStore>,
) {
    if !cli.rebuild_cache {
        return;
    }
    let dir = cache_directory(cli, config);
    if !dir.is_dir() {
        return;
    }
    if let Err(reason) = validate_cache_purge_path(&dir) {
        if !cli.quiet {
            tracing::warn!("refusing to purge cache at {}: {reason}", dir.display());
        }
        return;
    }
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        if !cli.quiet {
            tracing::warn!("could not purge cache at {}: {e}", dir.display());
        }
    } else if !cli.quiet {
        eprintln!("Purged cache at {}", dir.display());
    }
    *cache_store = open_cache_store(cli, config);
}

/// Refuse to `remove_dir_all` paths that look like project roots or the FS root.
fn validate_cache_purge_path(dir: &Path) -> Result<(), String> {
    let name = dir.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // Prefer directories that look like a cache (default name or explicit cache_dir).
    let looks_like_cache = name == DEFAULT_CACHE_DIR.trim_start_matches("./")
        || name == ".codehound-cache"
        || name.contains("codehound-cache")
        || name.contains("cache");
    if !looks_like_cache {
        return Err(
            "path does not look like a codehound cache directory (name must contain 'cache')"
                .into(),
        );
    }
    let canon = dir
        .canonicalize()
        .map_err(|e| format!("could not resolve path: {e}"))?;
    if canon.parent().is_none() {
        return Err("refusing to delete filesystem root".into());
    }
    // Refuse common sensitive roots if someone pointed --cache-dir at them.
    let forbidden = ["/etc", "/usr", "/bin", "/home", "/root", "/var", "/tmp"];
    let canon_str = canon.to_string_lossy();
    for f in forbidden {
        if canon_str == f {
            return Err(format!("refusing to delete system path {f}"));
        }
    }
    Ok(())
}

pub(crate) fn resolve_scan_paths(paths: &[String]) -> Result<Vec<PathBuf>> {
    paths.iter().map(|path| resolve_scan_path(path)).collect()
}

fn resolve_scan_path(path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(path);
    if path.extension().and_then(|ext| ext.to_str()) != Some(FIXTURE_EXTENSION) || !path.is_file() {
        return Ok(path);
    }

    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(path);
    };
    if parse_fixture(&text, &path).is_err() {
        return Ok(path);
    }

    materialize_fixture(&path)
}

fn run_prune_cache(
    cli: &Cli,
    registry: &Registry,
    lang_filter: &LanguageFilter,
    path_filters: &PathFilters,
    mut cache_store: Option<CacheStore>,
) -> Result<ExitCode> {
    let (entries, _skipped) = collect_entries_with(
        &FilesystemWalker,
        registry,
        &cli.paths,
        lang_filter,
        path_filters,
    )?;
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

fn apply_baseline_filter(cli: &Cli, config: Option<&CodehoundConfig>, result: &mut AnalysisResult) {
    if !baseline_loading_enabled(cli, config) {
        return;
    }
    let Some(baseline_path) = baseline_load_path(cli, config) else {
        return;
    };
    match Baseline::from_file(&baseline_path) {
        Ok(baseline) => {
            if baseline.version != codehound::engine::BASELINE_VERSION {
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
                    "warning: baseline {} was generated by codehound {}; current version is {}",
                    baseline_path.display(),
                    baseline.tool_version,
                    env!("CARGO_PKG_VERSION")
                );
            }
            let before = result.findings.len();
            if cli.show_baselined {
                // Mirror --show-ignored: keep baselined findings, mark as suppressed.
                for finding in &mut result.findings {
                    if baseline.contains_finding(finding) {
                        finding.severity = codehound::rules::Severity::Info;
                        finding.suppressed = true;
                        if !finding.message.ends_with(" (baselined)") {
                            finding.message.push_str(" (baselined)");
                        }
                    }
                }
                let baselined = result.findings.iter().filter(|f| f.suppressed).count();
                result.suppressed_count += baselined;
            } else {
                result
                    .findings
                    .retain(|finding| !baseline.contains_finding(finding));
                result.suppressed_count += before.saturating_sub(result.findings.len());
            }
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
    if cli.quiet {
        return Ok(());
    }
    let reporter: Box<dyn reporting::OutputReporter> = if cli.no_terminal {
        Box::new(reporting::NoTerminalReporter {
            options: reporting::text::TextOptions {
                verbose: cli.verbose,
                ..Default::default()
            },
            export_options: export_options.clone(),
            export_summary: *export_summary,
        })
    } else {
        match cli.format {
            OutputFormat::Text => Box::new(reporting::TextReporter {
                options: reporting::text::TextOptions {
                    color: true,
                    suppress_snippet: cli.no_snippet,
                    show_fingerprint: cli.show_fingerprint,
                    verbose: cli.verbose,
                    debug_timing: cli.debug_timing,
                },
            }),
            OutputFormat::Json => Box::new(reporting::JsonReporter {
                envelope: cli.json_envelope,
            }),
            OutputFormat::Sarif => Box::new(reporting::SarifReporter {
                compact: cli.sarif_compact,
            }),
        }
    };
    app_timing.measure("reporting", || reporter.report(result))?;
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

fn write_diagnostics_summary(cli: &Cli, result: &AnalysisResult) {
    if !cli.diagnostics_summary {
        return;
    }
    let Some(stats) = result.stats.as_ref() else {
        return;
    };
    let slowest = stats
        .timing
        .as_ref()
        .and_then(|t| t.phases.iter().max_by_key(|p| p.duration).map(|p| p.name));
    let total_ms = stats
        .timing
        .as_ref()
        .map(|t| t.total_wall_time.as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let slowest_str = slowest.unwrap_or("-");
    eprintln!(
        "scanned {} files | {} cached | {} fresh | {:.1}ms | slowest: {}",
        stats.files_scanned, stats.cache_hits, stats.cache_misses, total_ms, slowest_str,
    );
}

fn scan_exit_code(result: &AnalysisResult, fail_policy: codehound::core::FailPolicy) -> ExitCode {
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

#[cfg(test)]
mod tests {
    use super::{resolve_scan_path, resolve_scan_paths};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn resolve_scan_path_materializes_text_fixture_inputs() {
        let resolved = resolve_scan_path("tests/fixtures/go/perf/PERF-213-vulnerable.txt")
            .expect("materialize fixture path");
        assert_eq!(
            resolved.extension().and_then(|ext| ext.to_str()),
            Some("go")
        );
        assert!(
            resolved.exists(),
            "materialized file should exist: {}",
            resolved.display()
        );
    }

    #[test]
    fn resolve_scan_path_leaves_plain_text_files_unchanged() {
        let temp_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("resolve-scan-path-plain.txt");
        fs::write(&temp_path, "plain text, not a fixture").expect("write temp text file");

        let resolved = resolve_scan_path(temp_path.to_str().expect("utf8 temp path"))
            .expect("resolve plain text path");
        assert_eq!(resolved, temp_path);
    }

    #[test]
    fn scan_run_builds_via_run_config() {
        use codehound::engine::{RunConfigParams, ScanContextParams, build_run_config};

        let run_config = build_run_config(RunConfigParams {
            scan: ScanContextParams {
                bp_only: true,
                ..ScanContextParams::default()
            },
            include_tests: false,
        });
        assert!(run_config.scan_context.bad_practices_enabled);
        assert!(
            run_config
                .scan_context
                .only
                .as_ref()
                .is_some_and(|s| s.contains("BP-*"))
        );
    }

    #[test]
    fn resolve_scan_paths_preserves_path_order() {
        let resolved = resolve_scan_paths(&[
            "tests/fixtures/go/perf/PERF-213-safe.txt".to_string(),
            "src/app/run.rs".to_string(),
        ])
        .expect("resolve paths");

        assert_eq!(resolved.len(), 2);
        assert_eq!(
            resolved[0].extension().and_then(|ext| ext.to_str()),
            Some("go")
        );
        assert_eq!(resolved[1], PathBuf::from("src/app/run.rs"));
    }
}
