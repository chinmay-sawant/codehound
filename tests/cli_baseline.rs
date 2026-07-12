use clap::Parser;
use codehound::cli::Cli;

#[test]
fn baseline_flags_parse() {
    let cli = Cli::parse_from([
        "codehound",
        "--baseline",
        "--show-ignored",
        "--show-fingerprint",
        "--verbose",
        "--baseline-file",
        "custom-baseline.json",
        ".",
    ]);

    assert!(cli.baseline);
    assert!(!cli.no_baseline);
    assert!(cli.show_ignored);
    assert!(cli.show_fingerprint);
    assert!(cli.verbose);
    assert_eq!(
        cli.baseline_file.as_deref(),
        Some(std::path::Path::new("custom-baseline.json"))
    );
}

#[test]
fn baseline_and_no_baseline_conflict() {
    let err = Cli::try_parse_from(["codehound", "--baseline", "--no-baseline", "."]).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("cannot be used with") || msg.contains("conflicts"),
        "expected conflict error, got: {msg}"
    );
}
