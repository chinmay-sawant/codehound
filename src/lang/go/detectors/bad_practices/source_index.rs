//! Single-pass substring index for Go bad-practice detector hot paths.

/// Frequently scanned literals across the Go bad-practice bundle (one `contains` per needle).
pub const NEEDLES: &[&str] = &[
    " sync.Mutex",
    ".Add(",
    ".Error(",
    ".Unlock()",
    ".Warn(",
    "Logger.",
    "defer ",
    "fmt.Fprintf(",
    "fmt.Printf(",
    "go func",
    "log.",
    "recover()",
];

pub use crate::lang::source_index::SourceIndex;
