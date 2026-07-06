#![cfg(feature = "python")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::unique_temp_root;

use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;

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
    let result = analyzer.analyze_paths(&[&root], None).unwrap();
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
    let result = analyzer.analyze_paths(&[&root], None).unwrap();
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
    let result = analyzer.analyze_paths(&[&root], None).unwrap();
    let key = source_path.display().to_string();

    assert!(result.findings.is_empty());
    assert_eq!(result.source_cache.len(), 1);
    assert_eq!(result.source_cache.get(&key).map(|s| s.as_ref()), Some(""));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn analyze_paths_populates_source_cache_for_mixed_language_scan() {
    let root = unique_temp_root("source-cache-mixed-language");
    let go_dir = root.join("sample");
    let go_path = go_dir.join("safe.go");
    let py_path = root.join("sample.py");
    let go_source = r#"// Package sample exercises mixed-language source caching.
package sample

func add(a int, b int) int {
	return a + b
}
"#;
    let py_source = "import re\n\nfor item in items:\n    re.compile(item)\n";
    std::fs::create_dir_all(&go_dir).unwrap();
    std::fs::write(&go_path, go_source).unwrap();
    std::fs::write(&py_path, py_source).unwrap();

    let analyzer = Analyzer::builder()
        
        .scan_context(ScanContext::default())
        .build();
    let result = analyzer.analyze_paths(&[&root], None).unwrap();

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
