//! Crate-root error type for public library APIs.

use thiserror::Error;

use crate::engine::CacheError;

/// Kind of path-scoped I/O operation (for structured matching by consumers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOp {
    CreateDir,
    CreateFile,
    Rename,
    Read,
    Write,
    Remove,
    Other,
}

impl std::fmt::Display for IoOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CreateDir => "creating directory",
            Self::CreateFile => "creating file",
            Self::Rename => "renaming",
            Self::Read => "reading",
            Self::Write => "writing",
            Self::Remove => "removing",
            Self::Other => "I/O",
        })
    }
}

/// Unified error type for fallible [`crate`] library operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Path-scoped I/O failure (atomic writes, cache file ops, etc.).
    /// Prefer this over [`Error::Walk`] for non-walk failures.
    #[error("{op} {path}: {source}")]
    PathIo {
        path: String,
        op: IoOp,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Cache(#[from] CacheError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("failed to parse {path}: {detail}")]
    Parse { path: String, detail: String },

    #[error("failed to load tree-sitter grammar: {0}")]
    Grammar(String),

    /// Directory walk / path collection failures only.
    #[error("{0}")]
    Walk(String),

    #[error("{0}")]
    Config(String),
}

impl Error {
    pub fn path_io(path: impl Into<String>, op: IoOp, source: std::io::Error) -> Self {
        Self::PathIo {
            path: path.into(),
            op,
            source,
        }
    }
}

// ponytail: GrammarError was a one-variant wrapper with a single From impl.
// Replaced with bare String in the parser OnceLock types — less code, same safety.
