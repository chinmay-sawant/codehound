//! Crate-root error type for public library APIs.

use thiserror::Error;

use crate::engine::CacheError;
use crate::rules::FingerprintParseError;

/// Unified error type for fallible [`crate`] library operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Cache(#[from] CacheError),

    #[error(transparent)]
    Fingerprint(#[from] FingerprintParseError),

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

/// Failure to load a tree-sitter grammar at runtime.
#[derive(Debug, Clone, Error)]
pub enum GrammarError {
    #[error("failed to load tree-sitter grammar: {0}")]
    Load(String),
}

impl From<GrammarError> for Error {
    fn from(value: GrammarError) -> Self {
        Self::Grammar(value.to_string())
    }
}
