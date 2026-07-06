//! File I/O helpers: atomic writes.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::Error;

pub(crate) fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::Walk(format!("creating {}: {e}", parent.display())))?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| Error::Walk(format!("creating tmp file {}: {e}", tmp.display())))?;
        serde_json::to_writer_pretty(&mut f, value).map_err(Error::from)?;
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
