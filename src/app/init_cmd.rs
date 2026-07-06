use std::path::Path;
use std::process::ExitCode;

use super::exit_codes::{EXIT_CLEAN, EXIT_CONFIG, EXIT_INTERNAL};

pub fn init_subcommand() -> ExitCode {
    const TEMPLATE: &str = include_str!("../../templates/codehound.toml");
    let path = Path::new("codehound.toml");
    if path.is_file() {
        eprintln!("codehound.toml already exists in this directory");
        return ExitCode::from(EXIT_CONFIG);
    }
    if let Err(e) = std::fs::write(path, TEMPLATE) {
        eprintln!("failed to write codehound.toml: {e}");
        return ExitCode::from(EXIT_INTERNAL);
    }
    println!("wrote starter codehound.toml to {}", path.display());
    ExitCode::from(EXIT_CLEAN)
}
