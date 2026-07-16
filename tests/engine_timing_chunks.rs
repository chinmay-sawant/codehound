#![cfg(feature = "go")]

use std::sync::Arc;

use codehound::core::{LanguageId, ScanContext};
use codehound::engine::{Analyzer, ListEntrySource, SCAN_CHUNK_SIZE, ScanEntry};

#[test]
fn timing_collects_all_scan_chunks() {
    let root = std::env::temp_dir().join(format!("codehound-timing-chunks-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();

    let entries: Vec<ScanEntry> = (0..=SCAN_CHUNK_SIZE)
        .map(|index| {
            let path = root.join(format!("file-{index}.go"));
            std::fs::write(&path, "package main\n").unwrap();
            ScanEntry {
                path: Arc::from(path.as_path()),
                language: LanguageId::Go,
            }
        })
        .collect();

    let analyzer = Analyzer::builder()
        .scan_context(ScanContext {
            debug_timing: true,
            ..ScanContext::default()
        })
        .collect_stats(true)
        .entry_source(Box::new(ListEntrySource::new(entries)))
        .build();
    let result = analyzer
        .analyze_paths(&[&root], None)
        .expect("timed chunked scan");
    let timing = result.stats.expect("scan stats").timing.expect("timing");
    let file_reads = timing
        .phases
        .iter()
        .find(|phase| phase.name == "file_read")
        .expect("file_read timing phase");
    assert_eq!(file_reads.count, SCAN_CHUNK_SIZE + 1);

    std::fs::remove_dir_all(root).unwrap();
}
