//! Crate-root error type for public library APIs.

use thiserror::Error;

use crate::engine::CacheError;

/// Unified error type for fallible [`crate`] library operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Cache(#[from] CacheError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("failed to parse {path}: {detail}")]
    Parse { path: String, detail: String },

    #[error("failed to load tree-sitter grammar: {0}")]
    Grammar(String),

    #[error("{0}")]
    Walk(String),

    #[error("{0}")]
    Config(String),
}

// ponytail: GrammarError was a one-variant wrapper with a single From impl.
// Replaced with bare String in the parser OnceLock types — less code, same safety.
