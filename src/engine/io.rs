//! Shared engine I/O helpers.

use std::fs;
use std::io::Write;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use serde::Serialize;

use crate::error::{Error, IoOp};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static PARENT_DIR_SYNC_FAILURE: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

#[cfg(test)]
pub(crate) fn set_parent_dir_sync_failure_for_test(path: Option<&Path>) {
    let failure_path = PARENT_DIR_SYNC_FAILURE.get_or_init(|| Mutex::new(None));
    if let Ok(mut failure_path) = failure_path.lock() {
        *failure_path = path.map(Path::to_path_buf);
    }
}

#[cfg(test)]
fn parent_dir_sync_failure_is_injected(path: &Path) -> bool {
    PARENT_DIR_SYNC_FAILURE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .is_ok_and(|failure_path| failure_path.as_deref() == Some(path))
}

/// Atomically replace `path` with serialized JSON.
pub(crate) fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(Error::from)?;
    bytes.push(b'\n');
    write_atomic_bytes(path, &bytes)
}

/// Atomically replace `path` with bytes using a unique sibling temp file.
pub(crate) fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
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
    // The rename is already the logical commit. Reporting a later directory
    // sync error as a failed write makes callers roll back files while the
    // manifest has already been replaced.
    if let Err(error) = sync_parent_dir(path) {
        tracing::warn!(path = %path.display(), error = %error, "atomic replacement committed but parent directory sync failed");
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<(), Error> {
    #[cfg(test)]
    if parent_dir_sync_failure_is_injected(path) {
        return Err(Error::Config(
            "injected parent directory sync failure".to_string(),
        ));
    }
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn write_atomic_keeps_prior_file_when_directory_becomes_unwritable() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("codehound-atomic-{unique}"));
        fs::create_dir_all(&root).expect("mkdir");
        let path = root.join("diag.json");
        fs::write(&path, "{\"prior\":true}\n").expect("seed prior");

        let mut perms = fs::metadata(&root).expect("meta").permissions();
        perms.set_mode(0o555);
        fs::set_permissions(&root, perms).expect("readonly dir");

        let err = write_atomic(&path, &serde_json::json!({"next": true}));
        let mut restore = fs::metadata(&root).expect("meta").permissions();
        restore.set_mode(0o755);
        fs::set_permissions(&root, restore).expect("restore perms");

        assert!(err.is_err(), "unwritable directory must fail the replace");
        assert_eq!(
            fs::read_to_string(&path).expect("prior intact"),
            "{\"prior\":true}\n"
        );

        let _ = fs::remove_dir_all(root);
    }
}
