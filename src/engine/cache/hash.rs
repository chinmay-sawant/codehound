//! Content hashing and ISO-8601 timestamp helpers.

use std::time::SystemTime;

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

/// Public ISO-8601 timestamp generator used by other engine modules
/// (notably `walk.rs`) when stamping `cached_at` on freshly written
/// cache entries.
pub fn iso8601_now() -> String {
    iso8601_utc_now()
}

pub(super) fn iso8601_utc_now() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    iso8601_from_secs(secs)
}

pub(super) fn iso8601_from_mtime(mtime_secs: u64) -> String {
    iso8601_from_secs(mtime_secs)
}

fn iso8601_from_secs(secs: u64) -> String {
    let (year, month, day, hour, minute, second) = unix_epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn unix_epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        y as u32,
        m as u32,
        d as u32,
        hour as u32,
        minute as u32,
        second as u32,
    )
}
