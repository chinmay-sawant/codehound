//! File I/O helpers: mtime extraction and atomic writes.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::Serialize;

/// `(secs, nanos)` from a file's mtime, or `(0, 0)` when the mtime
/// cannot be determined.
pub(super) fn mtime_of_file(path: &str) -> std::io::Result<(u64, u32)> {
    let meta = fs::metadata(path)?;
    let mtime = meta.modified()?;
    let dur = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    Ok((dur.as_secs(), dur.subsec_nanos()))
}

pub(super) fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("creating tmp file {}", tmp.display()))?;
        let text = serde_json::to_string_pretty(value)
            .with_context(|| format!("serializing {}", path.display()))?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}
