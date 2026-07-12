//! Re-export Go analysis sinks (kept for embedder/compat paths).
//!
//! Canonical location: [`crate::lang::go::sinks`].

#[cfg(feature = "go")]
pub use crate::lang::go::sinks::*;
