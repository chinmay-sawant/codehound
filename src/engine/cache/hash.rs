//! Content hashing helpers.

use sha2::{Digest, Sha256};

/// Compute the SHA-256 of `source` formatted as `sha256:<hex>`.
pub fn content_hash(source: &str) -> String {
    let digest = Sha256::digest(source.as_bytes());
    format!("sha256:{digest:x}")
}

/// Derive a cache-key (filename) for a relative file path: lowercase
/// hex of `Sha256(path.as_bytes())`.
pub fn cache_key_for_path(rel_path: &str) -> String {
    let normalized = rel_path.replace('\\', "/");
    format!("{:x}", Sha256::digest(normalized.as_bytes()))
}