use std::path::Path;
use std::process::ExitCode;

use super::exit_codes::{EXIT_CLEAN, EXIT_CONFIG, EXIT_INTERNAL};

pub fn init_subcommand() -> ExitCode {
    const TEMPLATE: &str = include_str!("../../templates/slopguard.toml");
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
