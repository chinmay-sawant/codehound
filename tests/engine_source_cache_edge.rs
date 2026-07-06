#![cfg(feature = "python")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::unique_temp_root;

use std::sync::Arc;

use codehound::core::ScanContext;
use codehound::engine::Analyzer;

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
    let result = analyzer.analyze_paths(&[&root], None).unwrap();

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
    let result = analyzer.analyze_paths(&[&root], None).unwrap();
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
    let result = analyzer.analyze_paths(&[&root], None).unwrap();
    let key = source_path.display().to_string();

    let cached = result.source_cache.get(&key).unwrap();
    let cloned = Arc::clone(cached);

    assert!(Arc::ptr_eq(cached, &cloned));
    assert_eq!(cloned.as_ref(), source);

    std::fs::remove_dir_all(root).unwrap();
}
