use std::sync::Arc;
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
fn analyze_paths_populates_source_cache_for_mixed_language_scan() {
    let root = unique_temp_root("source-cache-mixed-language");
    let go_path = root.join("safe.go");
    let py_path = root.join("sample.py");
    let go_source = r#"package sample

func add(a int, b int) int {
	return a + b
}
"#;
    let py_source = "import re\n\nfor item in items:\n    re.compile(item)\n";
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&go_path, go_source).unwrap();
    std::fs::write(&py_path, py_source).unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths([&root]).unwrap();

    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    assert_eq!(result.source_cache.len(), 2);
    assert_eq!(
        result
            .source_cache
            .get(&go_path.display().to_string())
            .map(|s| s.as_ref()),
        Some(go_source)
    );
    assert_eq!(
        result
            .source_cache
            .get(&py_path.display().to_string())
            .map(|s| s.as_ref()),
        Some(py_source)
    );
    assert_eq!(
        result.source_cache_bytes(),
        go_source.len() + py_source.len()
    );
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].rule_id, "SLOP101");

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn analyze_paths_handles_unicode_and_omits_non_utf8_source_cache_entries() {
    let root = unique_temp_root("source-cache-unicode-non-utf8");
    let unicode_path = root.join("unicode.py");
    let invalid_path = root.join("invalid.py");
    let unicode_source = "name = 'नमस्ते'\nprint(name)\n";
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&unicode_path, unicode_source).unwrap();
    std::fs::write(&invalid_path, [0xff, 0xfe]).unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths([&root]).unwrap();

    assert!(result.findings.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].path, invalid_path);
    assert_eq!(
        result
            .source_cache
            .get(&unicode_path.display().to_string())
            .map(|s| s.as_ref()),
        Some(unicode_source)
    );
    assert!(
        !result
            .source_cache
            .contains_key(&invalid_path.display().to_string()),
        "invalid UTF-8 files should produce scan errors and no source cache entry"
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn analyze_paths_caches_large_utf8_sources() {
    let root = unique_temp_root("source-cache-large-file");
    let source_path = root.join("large.py");
    let mut source = String::with_capacity(10 * 1024 * 1024 + 128);
    source.push_str("name = 'large-source-cache-sentinel'\n");
    source.extend(std::iter::repeat_n('#', 10 * 1024 * 1024));
    source.push('\n');
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&source_path, &source).unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths([&root]).unwrap();
    let key = source_path.display().to_string();

    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    assert!(result.findings.is_empty());
    assert_eq!(
        result.source_cache.get(&key).map(|s| s.len()),
        Some(source.len())
    );
    assert_eq!(
        result.source_cache.get(&key).map(|s| s.as_ref()),
        Some(source.as_str())
    );
    assert_eq!(result.source_cache_bytes(), source.len());

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn source_cache_arc_clone_shares_source_allocation() {
    let root = unique_temp_root("source-cache-arc-sharing");
    let source_path = root.join("sample.py");
    let source = "import re\n\nfor item in items:\n    re.compile(item)\n";
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&source_path, source).unwrap();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths([&root]).unwrap();
    let key = source_path.display().to_string();

    let cached = result.source_cache.get(&key).unwrap();
    let cloned = Arc::clone(cached);

    assert!(Arc::ptr_eq(cached, &cloned));
    assert_eq!(cloned.as_ref(), source);

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
