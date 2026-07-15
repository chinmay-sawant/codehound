//! `codehound baseline list|prune|update|diff|save` subcommands.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use codehound::cli::{BaselineAction, Cli};
use codehound::engine::{
    AnalysisResult, Analyzer, BASELINE_FILE_NAME, Baseline, CacheSession, RunConfigParams,
    build_run_config,
};

use super::cache::open_cache_store;
use super::config::{baseline_load_path, load_config};
use super::exit_codes::EXIT_CLEAN;
use super::run::{resolve_scan_paths, scan_context_params_for_run};

pub(crate) fn run_baseline_command(cli: &Cli, action: &BaselineAction) -> Result<ExitCode> {
    match action {
        BaselineAction::List { path } => {
            let p = resolve_baseline_path(cli, path.as_deref())?;
            let baseline = Baseline::from_file(&p)
                .with_context(|| format!("load baseline {}", p.display()))?;
            println!(
                "Baseline {} ({} entries, tool {})",
                p.display(),
                baseline.entry_count(),
                baseline.tool_version
            );
            let mut rows: Vec<_> = baseline.iter_entries().collect();
            rows.sort_by(|a, b| {
                a.0.cmp(b.0)
                    .then(a.1.file.cmp(&b.1.file))
                    .then(a.1.line.cmp(&b.1.line))
            });
            for (rule, e) in rows {
                let reason = e.reason.as_deref().unwrap_or("-");
                let exp = e.expires.as_deref().unwrap_or("-");
                println!(
                    "  {rule:<12} {}:{}:{}  fp={}  reason={reason}  expires={exp}",
                    e.file, e.line, e.column, e.fingerprint
                );
            }
            Ok(ExitCode::from(EXIT_CLEAN))
        }
        BaselineAction::Prune { paths, path } => {
            let p = resolve_baseline_path(cli, path.as_deref())?;
            let mut baseline = Baseline::from_file(&p)
                .with_context(|| format!("load baseline {}", p.display()))?;
            let live = scan_live(cli, paths)?;
            let removed = baseline.prune_to_findings(&live.findings);
            baseline.to_file(&p)?;
            if !cli.quiet {
                println!(
                    "Pruned {removed} entr{} from {}",
                    if removed == 1 { "y" } else { "ies" },
                    p.display()
                );
            }
            Ok(ExitCode::from(EXIT_CLEAN))
        }
        BaselineAction::Update { paths, path } => {
            let p = resolve_baseline_path(cli, path.as_deref())?;
            let mut baseline = match Baseline::from_file(&p) {
                Ok(b) => b,
                Err(_) => Baseline::from_findings(&[]),
            };
            let live = scan_live(cli, paths)?;
            let (added, updated) = baseline.update_from_findings(&live.findings);
            baseline.to_file(&p)?;
            if !cli.quiet {
                println!(
                    "Updated baseline {}: +{added} added, {updated} fingerprint refresh, {} total",
                    p.display(),
                    baseline.entry_count()
                );
            }
            Ok(ExitCode::from(EXIT_CLEAN))
        }
        BaselineAction::Diff { paths, path } => {
            let p = resolve_baseline_path(cli, path.as_deref())?;
            let baseline = Baseline::from_file(&p)
                .with_context(|| format!("load baseline {}", p.display()))?;
            let live = scan_live(cli, paths)?;
            let new_f = baseline.new_findings(&live.findings);
            let stale = baseline.stale_entries(&live.findings);
            println!("Baseline diff vs {}:", p.display());
            println!("  new (live, not baselined): {}", new_f.len());
            for f in &new_f {
                println!("    + {} {}:{}:{}", f.rule_id, f.file, f.line, f.column);
            }
            println!("  stale (baselined, not live): {}", stale.len());
            for (rule, e) in &stale {
                println!("    - {rule} {}:{}:{}", e.file, e.line, e.column);
            }
            Ok(ExitCode::from(EXIT_CLEAN))
        }
        BaselineAction::Save { paths, path } => {
            let p = path
                .clone()
                .or_else(|| cli.baseline_file.clone())
                .unwrap_or_else(|| PathBuf::from(BASELINE_FILE_NAME));
            let live = scan_live(cli, paths)?;
            let baseline = Baseline::from_findings(&live.findings);
            let n = baseline.entry_count();
            baseline.to_file(&p)?;
            if !cli.quiet {
                println!("Baseline saved with {n} entries to {}", p.display());
            }
            Ok(ExitCode::from(EXIT_CLEAN))
        }
    }
}

fn resolve_baseline_path(cli: &Cli, override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = &cli.baseline_file {
        return Ok(p.clone());
    }
    let config = load_config(cli.config.as_deref())?;
    Ok(baseline_load_path(cli, config.as_ref())
        .unwrap_or_else(|| PathBuf::from(BASELINE_FILE_NAME)))
}

fn scan_live(cli: &Cli, paths: &[String]) -> Result<AnalysisResult> {
    let config = load_config(cli.config.as_deref())?;
    let run_config = build_run_config(RunConfigParams {
        scan: scan_context_params_for_run(cli, config.clone()),
        include_tests: cli.include_tests,
    });
    let analyzer = Analyzer::builder()
        .scan_context(run_config.scan_context)
        .path_filters(run_config.path_filters)
        .collect_stats(false)
        .build();
    let mut cache_store = open_cache_store(cli, config.as_ref());
    let scan_paths = resolve_scan_paths(paths)?;
    let res = analyzer.analyze_paths(
        &scan_paths,
        CacheSession::from_optional(cache_store.as_mut()),
    )?;
    Ok(res)
}
