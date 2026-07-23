use std::time::{SystemTime, UNIX_EPOCH};

use codehound::cwe::CweRef;
use codehound::export::{ExportOptions, export_findings};
use codehound::rules::{
    DetectorEvidence, Finding, FindingInputs, LineCol, Severity, TaintSinkInfo, TaintSourceInfo,
};

#[test]
fn exports_context_and_chunk_files() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("codehound-export-test-{unique}"));
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
    let findings = vec![
        Finding::new(FindingInputs::new(
            "CWE-89",
            "SQL injection via concatenated query",
            source_path.to_string_lossy().to_string(),
            LineCol { line: 4, column: 5 },
            "query string is built from untrusted input",
            Severity::Medium,
            std::borrow::Cow::Borrowed(cwe),
        ))
        .with_evidence(DetectorEvidence::TaintFlow {
            source: TaintSourceInfo {
                kind: "UserInput".to_string(),
                function: "r.URL.Query".to_string(),
                variable: "id".to_string(),
            },
            sink: TaintSinkInfo::new("SQLQuery", "database/sql.Query"),
            hops: 1,
            sanitized: false,
        })
        .with_confidence(0.7)
        .with_tags(vec!["heuristic".to_string(), "review-query".to_string()])
        .with_remediation("Use parameterized queries."),
    ];

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
    let context = std::fs::read_to_string(root.join("findings/functions/1.txt")).unwrap();
    let chunk = std::fs::read_to_string(root.join("chunks/Chunk_1_1.txt")).unwrap();
    assert!(
        context.contains("Fingerprint: codehound:2:CWE-89:"),
        "got: {context}"
    );
    assert!(
        chunk.contains("Fingerprint: codehound:2:CWE-89:"),
        "got: {chunk}"
    );
    for output in [&context, &chunk] {
        assert!(
            output.contains(
                "Evidence: {\"kind\":\"TaintFlow\",\"source\":{\"kind\":\"UserInput\",\"function\":\"r.URL.Query\",\"variable\":\"id\"},\"sink\":{\"kind\":\"SQLQuery\",\"function\":\"database/sql.Query\"},\"hops\":1,\"sanitized\":false}"
            ),
            "got: {output}"
        );
        assert!(output.contains("Confidence: 0.7"), "got: {output}");
        assert!(
            output.contains("Tags: heuristic, review-query"),
            "got: {output}"
        );
        assert!(
            output.contains("Remediation: Use parameterized queries."),
            "got: {output}"
        );
    }

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn export_refuses_to_overwrite_unowned_output_files() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("codehound-export-owned-test-{unique}"));
    let output_dir = root.join("contexts");
    let source_path = root.join("sample.go");
    std::fs::create_dir_all(&output_dir).unwrap();
    std::fs::write(&source_path, "package main\n").unwrap();
    std::fs::write(output_dir.join("1.txt"), "do not replace").unwrap();
    let findings = vec![Finding::new(FindingInputs::new(
        "CWE-89",
        "title",
        source_path.to_string_lossy().to_string(),
        LineCol { line: 1, column: 1 },
        "message",
        Severity::Medium,
        std::borrow::Cow::Borrowed(&[]),
    ))];

    let error = export_findings(
        &findings,
        &ExportOptions {
            export_context: true,
            export_chunks: false,
            chunk_size: 25,
            context_output_dir: output_dir.clone(),
            chunks_output_dir: root.join("chunks"),
        },
        &std::collections::HashMap::new(),
    )
    .expect_err("user-owned output must not be overwritten");

    assert!(error.to_string().contains("refusing to overwrite"));
    assert_eq!(
        std::fs::read_to_string(output_dir.join("1.txt")).unwrap(),
        "do not replace"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn export_preserves_foreign_files_and_replaces_owned_on_rerun() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("codehound-export-rerun-{unique}"));
    let output_dir = root.join("contexts");
    let source_path = root.join("sample.go");
    std::fs::create_dir_all(&output_dir).unwrap();
    std::fs::write(&source_path, "package main\nfunc main() {}\n").unwrap();
    std::fs::write(output_dir.join("notes.txt"), "foreign").unwrap();

    let findings = vec![Finding::new(FindingInputs::new(
        "CWE-89",
        "title",
        source_path.to_string_lossy().to_string(),
        LineCol { line: 1, column: 1 },
        "first",
        Severity::Medium,
        std::borrow::Cow::Borrowed(&[]),
    ))];
    let options = ExportOptions {
        export_context: true,
        export_chunks: false,
        chunk_size: 25,
        context_output_dir: output_dir.clone(),
        chunks_output_dir: root.join("chunks"),
    };

    export_findings(&findings, &options, &std::collections::HashMap::new()).unwrap();
    let first = std::fs::read_to_string(output_dir.join("1.txt")).unwrap();
    assert!(first.contains("first"));

    let findings = vec![Finding::new(FindingInputs::new(
        "CWE-89",
        "title",
        source_path.to_string_lossy().to_string(),
        LineCol { line: 1, column: 1 },
        "second",
        Severity::Medium,
        std::borrow::Cow::Borrowed(&[]),
    ))];
    export_findings(&findings, &options, &std::collections::HashMap::new()).unwrap();
    let second = std::fs::read_to_string(output_dir.join("1.txt")).unwrap();
    assert!(second.contains("second"));
    assert!(!second.contains("first"));
    assert_eq!(
        std::fs::read_to_string(output_dir.join("notes.txt")).unwrap(),
        "foreign"
    );
    assert!(output_dir.join(".codehound-export.json").is_file());

    std::fs::remove_dir_all(root).unwrap();
}
