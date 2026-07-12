//! Content hashing helpers.

use sha2::{Digest, Sha256};

use crate::engine::path_identity::normalize_project_path;

/// Lowercase hex encoding of a byte slice (no `0x` prefix).
///
/// Used instead of `format!("{digest:x}")` because sha2 0.11's digest
/// output (`hybrid_array::Array`) no longer implements [`std::fmt::LowerHex`].
pub(crate) fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0xf) as usize] as char);
    }
    out
}

/// Compute the SHA-256 of `source` formatted as `sha256:<hex>`.
pub fn content_hash(source: &str) -> String {
    let digest = Sha256::digest(source.as_bytes());
    format!("sha256:{}", hex_lower(digest))
}

/// Derive a cache-key (filename) for a relative file path: lowercase
/// hex of `Sha256(normalized_path.as_bytes())`.
pub fn cache_key_for_path(rel_path: &str) -> String {
    let normalized = normalize_project_path(rel_path);
    hex_lower(Sha256::digest(normalized.as_bytes()))
}
