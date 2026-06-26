use clap::Parser;
use slopguard::cli::Cli;
use slopguard::core::ScanContext;

#[test]
fn debug_timing_and_diagnostics_flags_parse() {
    let cli = Cli::parse_from([
        "slopguard",
        "--debug-timing",
        "--diagnostics",
        "diag.json",
        ".",
    ]);
    assert!(cli.debug_timing);
    assert_eq!(
        cli.diagnostics.as_deref(),
        Some(std::path::Path::new("diag.json"))
    );
}

#[test]
fn scan_context_collects_stats_when_debug_timing_set() {
    let ctx = ScanContext {
        debug_timing: true,
        ..ScanContext::default()
    };
    assert!(ctx.collect_stats());
    assert!(ctx.collect_detector_timing());
}

#[test]
fn scan_context_collects_stats_when_diagnostics_set() {
    let ctx = ScanContext {
        diagnostics: true,
        ..ScanContext::default()
    };
    assert!(ctx.collect_stats());
}
