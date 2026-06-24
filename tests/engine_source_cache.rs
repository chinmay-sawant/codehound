use std::time::{SystemTime, UNIX_EPOCH};

use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;
use slopguard::export::{ExportOptions, export_findings};

fn unique_temp_root(test_name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("slopguard-{test_name}-{unique}"))
}

#[test]
fn analyze_paths_populates_source_cache_for_scanned_files() {
    let root = unique_temp_root("source-cache-populated");
    let source_path = root.join("sample.py");
    let source = "import re\n\nfor item in items:\n    re.compile(item)\n";
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&source_path, source).unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths([&root]).unwrap();
    let key = source_path.display().to_string();

    assert_eq!(result.source_cache.len(), 1);
    assert_eq!(
        result.source_cache.get(&key).map(|s| s.as_ref()),
        Some(source)
    );
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SLOP101");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn analyze_paths_populates_source_cache_for_files_with_zero_findings() {
    let root = unique_temp_root("source-cache-zero-findings");
    let source_path = root.join("safe.py");
    let source =
        "import re\n\npattern = re.compile('x')\nfor item in items:\n    pattern.match(item)\n";
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&source_path, source).unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths([&root]).unwrap();
    let key = source_path.display().to_string();

    assert!(result.findings.is_empty());
    assert_eq!(result.source_cache.len(), 1);
    assert_eq!(
        result.source_cache.get(&key).map(|s| s.as_ref()),
        Some(source)
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn analyze_paths_populates_source_cache_for_empty_files() {
    let root = unique_temp_root("source-cache-empty-file");
    let source_path = root.join("empty.py");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&source_path, "").unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths([&root]).unwrap();
    let key = source_path.display().to_string();

    assert!(result.findings.is_empty());
    assert_eq!(result.source_cache.len(), 1);
    assert_eq!(result.source_cache.get(&key).map(|s| s.as_ref()), Some(""));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn export_uses_source_cache_after_source_file_is_removed() {
    let root = unique_temp_root("source-cache-export");
    let source_path = root.join("sample.py");
    let source = "import re\n\nfor item in items:\n    re.compile(item)\n";
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&source_path, source).unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths([&root]).unwrap();
    assert_eq!(result.findings.len(), 1);
    assert!(
        result
            .source_cache
            .contains_key(&source_path.display().to_string())
    );

    std::fs::remove_file(&source_path).unwrap();

    let summary = export_findings(
        &result.findings,
        &ExportOptions {
            export_context: true,
            export_chunks: true,
            chunk_size: 25,
            context_output_dir: root.join("findings/functions"),
            chunks_output_dir: root.join("chunks"),
        },
        &result.source_cache,
    )
    .unwrap();

    let context = std::fs::read_to_string(root.join("findings/functions/1.txt")).unwrap();
    let chunk = std::fs::read_to_string(root.join("chunks/Chunk_1_1.txt")).unwrap();

    assert_eq!(summary.context_files_written, 1);
    assert_eq!(summary.chunk_files_written, 1);
    assert!(context.contains("re.compile(item)"));
    assert!(chunk.contains("re.compile(item)"));

    std::fs::remove_dir_all(root).unwrap();
}
