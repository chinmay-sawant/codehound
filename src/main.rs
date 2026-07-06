use std::process::ExitCode;

use clap::Parser;
use codehound::cli::Cli;
use tracing_subscriber::EnvFilter;

mod app;

fn main() -> ExitCode {
    init_tracing();

    let cli = Cli::parse();

    match app::run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(app::EXIT_CONFIG)
        }
    }
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn,codehound=info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}
