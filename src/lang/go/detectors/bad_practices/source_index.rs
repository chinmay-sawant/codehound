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

/// Precomputed presence of [`NEEDLES`] for one source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIndex {
    flags: Vec<bool>,
}

impl Default for SourceIndex {
    fn default() -> Self {
        Self {
            flags: vec![false; NEEDLES.len()],
        }
    }
}

impl SourceIndex {
    pub fn build(source: &str) -> Self {
        let flags = NEEDLES
            .iter()
            .map(|needle| source.contains(needle))
            .collect();
        Self { flags }
    }

    #[inline]
    pub fn has(&self, needle: &str) -> bool {
        let Some(idx) = NEEDLES.iter().position(|n| *n == needle) else {
            return false;
        };
        self.flags.get(idx).copied().unwrap_or(false)
    }
}