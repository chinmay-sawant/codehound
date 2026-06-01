use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use colored::control::ShouldColorize;
use colored::control::set_override;
use slopguard::cli::{Cli, OutputFormat};
use slopguard::engine::Analyzer;
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

    let mut builder = Analyzer::builder().scan_context(cli.scan_context());
    if let Some(lang) = cli.lang.language_id() {
        builder = builder.language(lang);
    }
    let analyzer = builder.build();

    let result = analyzer.analyze_paths(&cli.paths)?;

    match cli.format {
        OutputFormat::Text => reporting::text::print(&result)?,
        OutputFormat::Json => reporting::json::print(&result)?,
        OutputFormat::Sarif => reporting::sarif::print(&result)?,
    }

    Ok(if result.should_fail(analyzer.scan_context().fail_policy) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
