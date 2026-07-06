//! Collect source paths and scan files (parallel parse + detect).

mod analyze;
mod entry;
mod parallel;
mod scan_entry;
mod scratch;

pub use entry::{EntrySource, FilesystemWalker, ListEntrySource, ScanEntry, collect_entries};
pub(crate) use parallel::{MergedScan, scan_entries_parallel};
pub use scratch::scratch_contains;
