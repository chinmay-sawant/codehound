use std::path::Path;
use std::process::ExitCode;

use super::exit_codes::{EXIT_CLEAN, EXIT_CONFIG, EXIT_INTERNAL};

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

# Test files (*_test.*) are excluded by default; set to false to include them.
# exclude_tests = false

# Baselines are enabled by default and auto-discovered upward from the current directory.
# [slopguard.baseline]
# enabled = true
# path = \".slopguard-baseline.json\"

# Bad-practice rules (BP-*) are enabled by default.
# [slopguard.bad_practices]
# enabled = true
# severity = \"low\"

# Incremental analysis cache is enabled by default. SlopGuard stores per-file
# results in `.slopguard-cache/` next to the project root and reuses them on
# subsequent runs when the file's content hash has not changed.
# [slopguard.cache]
# enabled = true
# path = \".slopguard-cache\"
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
