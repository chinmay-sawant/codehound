//! File I/O helpers: mtime extraction and atomic writes.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use serde::Serialize;

use crate::Error;

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

pub(super) fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::Walk(format!("creating {}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| Error::Walk(format!("creating tmp file {}: {e}", tmp.display())))?;
        let text = serde_json::to_string_pretty(value).map_err(Error::from)?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path).map_err(|e| {
        Error::Walk(format!(
            "renaming {} -> {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(())
}
