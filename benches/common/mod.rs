use std::path::{Path, PathBuf};

use slopguard::core::ScanContext;
use slopguard::engine::{Analyzer, CacheStore};
use slopguard::rules::Finding;

pub fn unique_cache_dir(label: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("slopguard-bench-{label}-{nanos}"))
}

pub fn run_scan_with_cache(root: &Path, cache: Option<&mut CacheStore>) -> Vec<Finding> {
    let analyzer = Analyzer::builder()
        .with_default_filter()
        .scan_context(ScanContext::default())
        .build();
    analyzer
        .analyze_paths([root], cache)
        .expect("scan should succeed")
        .findings
}
