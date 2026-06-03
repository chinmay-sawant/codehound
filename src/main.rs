use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use colored::control::ShouldColorize;
use colored::control::set_override;
use slopguard::cli::{Cli, OutputFormat};
use slopguard::engine::{Analyzer, load_discovered_config, resolve_language_filter};
use slopguard::export::export_findings;
use slopguard::reporting;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    init_tracing();

    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,slopguard=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}

fn run(cli: Cli) -> Result<ExitCode> {
    if cli.no_color || !ShouldColorize::from_env().should_colorize() {
        set_override(false);
    }

    let config = load_discovered_config()?;
    let registry = slopguard::engine::Registry::default();
    let lang_filter = resolve_language_filter(cli.lang.language_id(), config.as_ref(), &registry)?;

    let analyzer = Analyzer::builder()
        .scan_context(cli.scan_context(config))
        .language_filter(lang_filter)
        .build();

    let result = analyzer.analyze_paths(&cli.paths)?;
    let export_options = cli.export_options();
    let export_summary = export_findings(&result.findings, &export_options)?;

    if !cli.no_terminal {
        match cli.format {
            OutputFormat::Text => reporting::text::print(&result)?,
            OutputFormat::Json => reporting::json::print(&result)?,
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
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
