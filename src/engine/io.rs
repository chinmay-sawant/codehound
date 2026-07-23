//! Shared engine I/O helpers.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::error::{Error, IoOp};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Atomically replace `path` with serialized JSON.
pub(crate) fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(Error::from)?;
    bytes.push(b'\n');
    write_atomic_bytes(path, &bytes)
}

/// Atomically replace `path` with bytes without sharing a temporary filename
/// with another process writing the same directory.
pub(crate) fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::path_io(parent.display().to_string(), IoOp::CreateDir, e))?;
    }
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("output");
    let tmp = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| Error::path_io(tmp.display().to_string(), IoOp::CreateFile, e))?;
        f.write_all(bytes)
            .map_err(|e| Error::path_io(tmp.display().to_string(), IoOp::Write, e))?;
        f.sync_all()
            .map_err(|e| Error::path_io(tmp.display().to_string(), IoOp::Write, e))?;
    }
    if let Err(error) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(Error::path_io(
            path.display().to_string(),
            IoOp::Rename,
            error,
        ));
    }
    sync_parent_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<(), Error> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| Error::path_io(parent.display().to_string(), IoOp::Write, error))
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<(), Error> {
    // ponytail: directory fsync is unavailable on this platform; the renamed
    // file itself was synced before replacement and remains the durable unit.
    Ok(())
}
