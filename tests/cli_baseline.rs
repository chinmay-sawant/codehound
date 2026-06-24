use clap::Parser;
use slopguard::cli::Cli;

#[test]
fn baseline_flags_parse() {
    let cli = Cli::parse_from([
        "slopguard",
        "--baseline",
        "--no-baseline",
        "--show-ignored",
        "--baseline-file",
        "custom-baseline.json",
        ".",
    ]);

    assert!(cli.generate_baseline());
    assert!(cli.no_baseline);
    assert!(cli.show_ignored);
    assert_eq!(
        cli.baseline_file.as_deref(),
        Some(std::path::Path::new("custom-baseline.json"))
    );
}
