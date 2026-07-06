use std::path::{Path, PathBuf};

use codehound::core::ScanContext;
use codehound::engine::{Analyzer, CacheSession, CacheStore};
use codehound::rules::Finding;

pub fn unique_cache_dir(label: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("codehound-bench-{label}-{nanos}"))
}

pub fn run_scan_with_cache(root: &Path, cache: Option<&mut CacheStore>) -> Vec<Finding> {
    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    analyzer
        .analyze_paths(&[root], CacheSession::from_optional(cache))
        .expect("scan should succeed")
        .findings
}
