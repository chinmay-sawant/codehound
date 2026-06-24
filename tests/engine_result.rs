use std::path::PathBuf;
use std::sync::Arc;

use slopguard::core::FailPolicy;
use slopguard::engine::{AnalysisResult, ScanError, ScanErrorKind};

#[test]
fn should_fail_returns_false_when_no_findings() {
    let result = AnalysisResult::default();
    assert!(!result.should_fail(FailPolicy::MediumAsErrors));
}

#[test]
fn scan_error_displays_path_and_message() {
    let e = ScanError {
        path: PathBuf::from("/tmp/x.go"),
        kind: ScanErrorKind::Io,
        message: "permission denied".to_string(),
    };
    assert_eq!(format!("{e}"), "/tmp/x.go: permission denied");
}

#[test]
fn error_kind_maps_to_exit_codes() {
    assert_eq!(ScanErrorKind::Io.exit_code(), 3);
    assert_eq!(ScanErrorKind::Encoding.exit_code(), 3);
    assert_eq!(ScanErrorKind::Parse.exit_code(), 3);
    assert_eq!(ScanErrorKind::Engine.exit_code(), 3);
}

#[test]
fn analysis_result_carries_errors_field() {
    let result = AnalysisResult {
        source_cache: std::collections::HashMap::new(),
        findings: vec![],
        errors: vec![ScanError {
            path: PathBuf::from("a.go"),
            kind: ScanErrorKind::Encoding,
            message: "not utf-8".to_string(),
        }],
        suppressed_count: 0,
        stats: None,
    };
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].kind, ScanErrorKind::Encoding);
}

#[test]
fn source_cache_bytes_tracks_cached_source_memory() {
    let mut result = AnalysisResult::default();
    result.source_cache.insert("a.go".into(), Arc::from("abc"));
    result.source_cache.insert("b.go".into(), Arc::from("नमस्ते"));

    assert_eq!(result.source_cache_bytes(), "abc".len() + "नमस्ते".len());
}
