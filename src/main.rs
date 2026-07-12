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
            // Prefer Error kind when available; fall back to config for clap/anyhow.
            let code = err
                .downcast_ref::<codehound::Error>()
                .map(app::exit_code_for_error)
                .unwrap_or(app::EXIT_CONFIG);
            ExitCode::from(code)
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
