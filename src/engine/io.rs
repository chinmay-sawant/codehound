//! Shared engine I/O helpers.

use std::fs;
use std::io::Write;
use std::path::Path;

use serde::Serialize;

use crate::error::{Error, IoOp};

pub(crate) fn write_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| Error::path_io(parent.display().to_string(), IoOp::CreateDir, e))?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| Error::path_io(tmp.display().to_string(), IoOp::CreateFile, e))?;
        serde_json::to_writer_pretty(&mut f, value).map_err(Error::from)?;
        f.write_all(b"\n")?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, path)
        .map_err(|e| Error::path_io(path.display().to_string(), IoOp::Rename, e))?;
    Ok(())
}
