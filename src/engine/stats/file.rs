//! Per-file statistics produced during scanning.

#[derive(Debug, Default, Clone)]
pub(crate) struct FileStats {
    pub bytes: u64,
    pub lines: u64,
}

impl FileStats {
    pub fn from_source(source: &str) -> Self {
        Self {
            bytes: source.len() as u64,
            lines: source.lines().count() as u64,
        }
    }
}
