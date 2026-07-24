//! Regression: export context for project-relative finding paths.
//!
//! Findings store paths relative to the scanned project root. When the scan
//! target is outside the process cwd (the `make run` / `SCAN_PATH` case),
//! export must use the retained source cache — not cwd-relative disk reads.

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::unique_temp_root;

use codehound::core::ScanContext;
use codehound::engine::Analyzer;
use codehound::export::{ExportOptions, export_findings};

#[test]
fn export_context_works_for_relative_paths_when_sources_retained() {
    let root = unique_temp_root("source-cache-export-go");
    let pkg = root.join("internal");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/export-test\n\ngo 1.22\n").unwrap();
    // BP-1: discarded error return (explicit blank assignment).
    std::fs::write(
        pkg.join("handler.go"),
        r#"package internal

import "os"

func Load(path string, data []byte) {
	_ = os.WriteFile(path, data, 0644)
}
"#,
    )
    .unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext {
            retain_sources: true,
            // Keep the run focused on a known finding for a stable assertion.
            only: Some(["BP-1".to_string()].into_iter().collect()),
            ..ScanContext::default()
        })
        .build();
    let result = analyzer.analyze_paths(&[&root], None).unwrap();
    assert!(
        !result.findings.is_empty(),
        "expected BP-1 finding, got none"
    );

    // Project-relative identity — not an absolute path under /tmp.
    let finding_file = &result.findings[0].file;
    assert!(
        finding_file.ends_with("internal/handler.go")
            || finding_file == "internal/handler.go"
            || finding_file.ends_with("handler.go"),
        "expected project-relative finding path, got {finding_file}"
    );
    assert!(
        result.source_cache.contains_key(finding_file),
        "source_cache must key by finding.file ({finding_file}); keys={:?}",
        result.source_cache.keys().collect::<Vec<_>>()
    );

    let out = unique_temp_root("source-cache-export-go-out");
    let summary = export_findings(
        &result.findings,
        &ExportOptions {
            export_context: true,
            export_chunks: true,
            chunk_size: 25,
            context_output_dir: out.join("findings/functions"),
            chunks_output_dir: out.join("chunks"),
        },
        &result.source_cache,
    )
    .unwrap();

    assert_eq!(summary.context_files_written, result.findings.len());
    assert!(summary.chunk_files_written >= 1);

    let context = std::fs::read_to_string(out.join("findings/functions/1.txt")).unwrap();
    assert!(
        !context.contains("<context unavailable>"),
        "context must include source, got:\n{context}"
    );
    assert!(
        context.contains("os.Open") || context.contains("Load"),
        "expected source snippet, got:\n{context}"
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(out);
}

#[test]
fn export_without_source_cache_cannot_resolve_foreign_relative_paths() {
    // Documents why retain_sources must be true for export: relative finding
    // paths are not readable from a foreign cwd.
    let findings = vec![codehound::rules::Finding::new(
        codehound::rules::FindingInputs::new(
            "BP-1",
            "Discarded Error Return",
            "internal/handler.go",
            codehound::rules::LineCol {
                line: 5,
                column: 2,
            },
            "discarded error return",
            codehound::rules::Severity::Low,
            std::borrow::Cow::Borrowed(&[]),
        ),
    )];

    let out = unique_temp_root("export-no-cache-out");
    export_findings(
        &findings,
        &ExportOptions {
            export_context: true,
            export_chunks: false,
            chunk_size: 25,
            context_output_dir: out.join("findings/functions"),
            chunks_output_dir: out.join("chunks"),
        },
        &std::collections::HashMap::new(),
    )
    .unwrap();

    let context = std::fs::read_to_string(out.join("findings/functions/1.txt")).unwrap();
    assert!(
        context.contains("<context unavailable>"),
        "empty cache + relative path must fail open, got:\n{context}"
    );
    let _ = std::fs::remove_dir_all(out);
}
