//! Scan statistics and operational metrics.

mod file;
mod scan;

pub(crate) use file::FileStats;
pub use scan::ScanStats;
