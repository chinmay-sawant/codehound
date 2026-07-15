//! Per-file statistics produced during scanning.

#[derive(Debug, Default, Clone)]
pub(crate) struct FileStats {
    pub bytes: u64,
    pub lines: u64,
}

impl FileStats {
    pub fn from_source(source: &str) -> Self {
        let bytes = source.as_bytes();
        let count = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
        let lines = if bytes.is_empty() {
            0
        } else if bytes[bytes.len() - 1] == b'\n' {
            count
        } else {
            count + 1
        };
        Self {
            bytes: bytes.len() as u64,
            lines,
        }
    }
}
