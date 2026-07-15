//! Collect source paths and scan files (parallel parse + detect).

mod analyze;
mod entry;
mod parallel;
mod scan_entry;
mod scratch;

pub(crate) use analyze::filter_findings;
pub use entry::{
    EntrySource, FilesystemWalker, ListEntrySource, ScanEntry, collect_entries,
    collect_entries_with,
};
pub(crate) use parallel::{MergedScan, scan_entries_parallel};
pub use scratch::scratch_contains;
