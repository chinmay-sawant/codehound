//! Content hashing helpers.

use sha2::{Digest, Sha256};

/// Compute the SHA-256 of `source` formatted as `sha256:<hex>`.
pub fn content_hash(source: &str) -> String {
    let digest = Sha256::digest(source.as_bytes());
    format!("sha256:{}", hex_lower(&digest))
}

/// Derive a cache-key (filename) for a relative file path: lowercase
/// hex of `Sha256(path.as_bytes())`.
pub fn cache_key_for_path(rel_path: &str) -> String {
    let normalized = rel_path.replace('\\', "/");
    hex_lower(&Sha256::digest(normalized.as_bytes()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ponytail: iso8601_utc_now / from_secs moved to engine::time (jiff)
