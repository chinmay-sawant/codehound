//! G4 optional typed / package-graph facts.

use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use codehound::cli::Cli;
use codehound::core::ScanContext;
use codehound::engine::{Analyzer, ScanContextParams, build_scan_context};
use codehound::lang::go::typed::{self, TypedLoadStatus};

fn go_available() -> bool {
    if Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return true;
    }
    std::path::Path::new("/usr/local/go/bin/go").is_file()
        || std::path::Path::new("/usr/bin/go").is_file()
}

fn fixture_module() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/go/typed_mod")
}

#[test]
fn typed_defaults_off() {
    let ctx = build_scan_context(ScanContextParams::default());
    assert!(!ctx.typed_enabled);
}

#[test]
fn typed_cli_enables() {
    let cli = Cli::try_parse_from(["codehound", "--typed", "."]).expect("parse");
    assert!(cli.typed);
    let ctx = build_scan_context(ScanContextParams {
        typed: true,
        ..ScanContextParams::default()
    });
    assert!(ctx.typed_enabled);
}

#[test]
fn no_typed_overrides() {
    let ctx = build_scan_context(ScanContextParams {
        typed: true,
        no_typed: true,
        ..ScanContextParams::default()
    });
    assert!(!ctx.typed_enabled);
}

#[test]
fn fingerprint_includes_typed() {
    let off = ScanContext {
        typed_enabled: false,
        ..ScanContext::default()
    }
    .rule_config_fingerprint();
    let on = ScanContext {
        typed_enabled: true,
        ..ScanContext::default()
    }
    .rule_config_fingerprint();
    assert_ne!(off, on);
}

#[test]
fn load_fixture_module_when_go_present() {
    if !go_available() {
        eprintln!("skip: go toolchain not available");
        return;
    }
    // Prefer known go binary for load helper.
    if std::path::Path::new("/usr/local/go/bin/go").is_file() {
        unsafe {
            std::env::set_var("CODEHOUND_GO", "/usr/local/go/bin/go");
        }
    }
    let root = fixture_module();
    assert!(
        root.join("go.mod").is_file(),
        "missing fixture {}",
        root.display()
    );
    let facts = typed::TypedFacts::new();
    let status = typed::load_project_facts(&root, &facts);
    match status {
        TypedLoadStatus::Ready {
            packages, files, ..
        } => {
            assert!(packages >= 1, "packages={packages}");
            assert!(files >= 1, "files={files}");
            let main = root.join("main.go").canonicalize().expect("canon");
            let pkg = facts.package_path_for_file(&main);
            assert!(
                pkg.is_some(),
                "expected package path for main.go, status={status:?}"
            );
        }
        other => panic!("expected Ready, got {other:?}"),
    }
}

#[test]
fn scan_with_typed_does_not_abort() {
    if !go_available() {
        eprintln!("skip: go toolchain not available");
        return;
    }
    if std::path::Path::new("/usr/local/go/bin/go").is_file() {
        unsafe {
            std::env::set_var("CODEHOUND_GO", "/usr/local/go/bin/go");
        }
    }
    let root = fixture_module();
    let analyzer = Analyzer::builder()
        .scan_context(ScanContext {
            typed_enabled: true,
            only: Some(["PERF-1"].iter().map(|s| (*s).to_string()).collect()),
            ..ScanContext::default()
        })
        .build();
    let result = analyzer
        .analyze_paths(&[root.as_path()], None)
        .expect("scan");
    let _ = result.findings.len();
}
