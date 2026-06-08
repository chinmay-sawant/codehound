use std::time::{SystemTime, UNIX_EPOCH};

use slopguard::cwe::CweRef;
use slopguard::export::{ExportOptions, export_findings};
use slopguard::rules::{Finding, LineCol, Severity};

#[test]
fn exports_context_and_chunk_files() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("slopguard-export-test-{unique}"));
    let source_path = root.join("sample.go");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        &source_path,
        "package main\n\nfunc main() {\n    s += x\n}\n",
    )
    .unwrap();

    let cwe: &'static [CweRef] = Box::leak(Box::new([CweRef::new(
        89,
        "Improper Neutralization of Special Elements used in an SQL Command",
        "https://cwe.mitre.org/data/definitions/89.html",
    )]));
    let findings = vec![Finding::new(
        "CWE-89",
        "SQL injection via concatenated query",
        source_path.to_string_lossy().to_string(),
        LineCol { line: 4, column: 5 },
        "query string is built from untrusted input",
        Severity::Medium,
        std::borrow::Cow::Borrowed(cwe),
    )];

    let summary = export_findings(
        &findings,
        &ExportOptions {
            export_context: true,
            export_chunks: true,
            chunk_size: 25,
            context_output_dir: root.join("findings/functions"),
            chunks_output_dir: root.join("chunks"),
        },
        &std::collections::HashMap::new(),
    )
    .unwrap();

    assert_eq!(summary.context_files_written, 1);
    assert_eq!(summary.chunk_files_written, 1);
    assert!(root.join("findings/functions/1.txt").exists());
    assert!(root.join("chunks/Chunk_1_1.txt").exists());

    std::fs::remove_dir_all(root).unwrap();
}
