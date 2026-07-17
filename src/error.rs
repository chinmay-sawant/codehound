//! Crate-root error type for public library APIs.

use thiserror::Error;

use crate::engine::CacheError;

/// Kind of path-scoped I/O operation (for structured matching by consumers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOp {
    /// Creating a directory.
    CreateDir,
    /// Creating a file.
    CreateFile,
    /// Renaming a path.
    Rename,
    /// Reading a path.
    Read,
    /// Writing a path.
    Write,
    /// Removing a path.
    Remove,
    /// Other / unclassified I/O.
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
    /// Unscoped standard I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Path-scoped I/O failure (atomic writes, cache file ops, etc.).
    /// Prefer this over [`Error::Walk`] for non-walk failures.
    #[error("{op} {path}: {source}")]
    PathIo {
        /// Path involved in the failure.
        path: String,
        /// Operation that failed.
        op: IoOp,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Incremental analysis cache failure.
    #[error(transparent)]
    Cache(#[from] CacheError),

    /// JSON serialization or deserialization failure.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Source parse failure for a specific file.
    #[error("failed to parse {path}: {detail}")]
    Parse {
        /// File that failed to parse.
        path: String,
        /// Parser detail message.
        detail: String,
    },

    /// Tree-sitter grammar load failure.
    #[error("failed to load tree-sitter grammar: {0}")]
    Grammar(String),

    /// Directory walk / path collection failures only.
    #[error("{0}")]
    Walk(String),

    /// Configuration discovery or validation failure.
    #[error("{0}")]
    Config(String),
}

impl Error {
    /// Construct a path-scoped I/O error with operation metadata.
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
