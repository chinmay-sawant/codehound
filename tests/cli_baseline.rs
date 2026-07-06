use clap::Parser;
use codehound::cli::Cli;

#[test]
fn baseline_flags_parse() {
    let cli = Cli::parse_from([
        "codehound",
        "--baseline",
        "--no-baseline",
        "--show-ignored",
        "--show-fingerprint",
        "--verbose",
        "--baseline-file",
        "custom-baseline.json",
        ".",
    ]);

    assert!(cli.baseline);
    assert!(cli.no_baseline);
    assert!(cli.show_ignored);
    assert!(cli.show_fingerprint);
    assert!(cli.verbose);
    assert_eq!(
        cli.baseline_file.as_deref(),
        Some(std::path::Path::new("custom-baseline.json"))
    );
}
