//! Verify that each [`OutputReporter`] implementation writes structurally
//! valid output through the trait's `report()` method — the same dispatch
//! path used by `app/run.rs`.

use std::borrow::Cow;

use slopguard::engine::AnalysisResult;
use slopguard::export::{ExportOptions, ExportSummary};
use slopguard::reporting::text::TextOptions;
use slopguard::reporting::{
    JsonReporter, NoTerminalReporter, OutputReporter, SarifReporter, TextReporter,
};
use slopguard::rules::{Finding, FindingInputs, LineCol, Severity};

#[path = "helpers/mod.rs"]
mod helpers;

fn sample_result() -> AnalysisResult {
    helpers::reporting::sample_result(vec![
        Finding::new(FindingInputs::new(
            "CWE-22",
            "Path traversal",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        )),
        Finding::new(FindingInputs::new(
            "CWE-89",
            "SQL injection",
            "b.go",
            LineCol { line: 2, column: 3 },
            "msg2",
            Severity::Critical,
            Cow::Borrowed(&[]),
        )),
    ])
}

#[test]
fn text_reporter_via_trait_succeeds() {
    let r = sample_result();
    let reporter = TextReporter {
        options: TextOptions {
            suppress_snippet: true,
            ..TextOptions::default()
        },
    };
    assert!(reporter.report(&r).is_ok());
}

#[test]
fn json_reporter_via_trait_succeeds() {
    let r = sample_result();
    let reporter = JsonReporter { envelope: false };
    assert!(reporter.report(&r).is_ok());
}

#[test]
fn json_envelope_reporter_via_trait_succeeds() {
    let r = sample_result();
    let reporter = JsonReporter { envelope: true };
    assert!(reporter.report(&r).is_ok());
}

#[test]
fn sarif_reporter_via_trait_succeeds() {
    let r = sample_result();
    let reporter = SarifReporter { compact: false };
    assert!(reporter.report(&r).is_ok());
}

#[test]
fn sarif_compact_reporter_via_trait_succeeds() {
    let r = sample_result();
    let reporter = SarifReporter { compact: true };
    assert!(reporter.report(&r).is_ok());
}

#[test]
fn no_terminal_reporter_via_trait_succeeds() {
    let r = sample_result();
    let reporter = NoTerminalReporter {
        options: TextOptions {
            suppress_snippet: true,
            ..TextOptions::default()
        },
        export_options: ExportOptions {
            export_context: true,
            export_chunks: false,
            chunk_size: 100,
            context_output_dir: std::path::PathBuf::from("context"),
            chunks_output_dir: std::path::PathBuf::from("chunks"),
        },
        export_summary: ExportSummary {
            context_files_written: 2,
            chunk_files_written: 0,
        },
    };
    assert!(reporter.report(&r).is_ok());
}

#[test]
fn all_reporters_via_trait_dispatch_succeed() {
    let r = sample_result();
    let reporters: [&dyn OutputReporter; 5] = [
        &TextReporter {
            options: TextOptions {
                suppress_snippet: true,
                ..TextOptions::default()
            },
        },
        &JsonReporter { envelope: false },
        &JsonReporter { envelope: true },
        &SarifReporter { compact: false },
        &SarifReporter { compact: true },
    ];
    for (i, reporter) in reporters.iter().enumerate() {
        assert!(
            reporter.report(&r).is_ok(),
            "reporter[{i}] failed via trait dispatch"
        );
    }
}
