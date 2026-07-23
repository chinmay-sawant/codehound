//! Staged export ownership tracking.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::engine::write_atomic;

const OWNERSHIP_FILE: &str = ".codehound-export.json";
static STAGE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static FAIL_AFTER_NEW_RENAMES: AtomicU64 = AtomicU64::new(u64::MAX);

#[derive(Debug, Serialize, Deserialize)]
struct Ownership {
    files: Vec<String>,
}

pub(super) struct OutputStage {
    output_dir: PathBuf,
    stage_dir: PathBuf,
    previous: HashSet<String>,
    next: HashSet<String>,
    preserve_stage_on_drop: bool,
}

impl OutputStage {
    pub(super) fn create(
        output_dir: &Path,
        files: impl IntoIterator<Item = String>,
    ) -> Result<Self, Error> {
        fs::create_dir_all(output_dir)?;
        let ownership_path = output_dir.join(OWNERSHIP_FILE);
        let previous = if ownership_path.is_file() {
            let bytes = fs::read(&ownership_path)?;
            validated_names(
                serde_json::from_slice::<Ownership>(&bytes)?.files,
                "ownership manifest",
            )?
        } else {
            HashSet::new()
        };
        let next = validated_names(files, "generated export")?;
        for name in &next {
            let path = output_dir.join(name);
            match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    if !previous.contains(name) {
                        return Err(Error::Config(format!(
                            "refusing to overwrite user-owned export file {}",
                            path.display()
                        )));
                    }
                    if !metadata.file_type().is_file() {
                        return Err(Error::Config(format!(
                            "refusing to replace non-file owned export path {}",
                            path.display()
                        )));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        let sequence = STAGE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let stage_dir = output_dir.join(format!(
            ".codehound-stage-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&stage_dir)?;
        Ok(Self {
            output_dir: output_dir.to_path_buf(),
            stage_dir,
            previous,
            next,
            preserve_stage_on_drop: false,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.stage_dir
    }

    pub(super) fn commit(mut self) -> Result<(), Error> {
        self.sync_staged_files()?;
        let backup_dir = self.stage_dir.join(".codehound-previous");
        fs::create_dir(&backup_dir)?;
        let mut moved_previous = Vec::new();
        for name in &self.previous {
            let output_path = self.output_dir.join(name);
            match fs::symlink_metadata(&output_path) {
                Ok(metadata) if metadata.file_type().is_file() => {
                    if let Err(error) = fs::rename(&output_path, backup_dir.join(name)) {
                        return Err(self.rollback(&backup_dir, &[], &moved_previous, error.into()));
                    }
                    moved_previous.push(name.clone());
                }
                Ok(_) => {
                    return Err(self.rollback(
                        &backup_dir,
                        &[],
                        &moved_previous,
                        Error::Config(format!(
                            "owned export path is no longer a regular file: {}",
                            output_path.display()
                        )),
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(self.rollback(&backup_dir, &[], &moved_previous, error.into()));
                }
            }
        }

        // ponytail: whole-directory export cannot be crash-atomic without changing the public
        // layout (caller-owned dir of many files). We stage + backup + per-file rename with
        // rollback for normal failures. Ceiling: a hard crash mid multi-rename can leave a
        // partial replace; upgrade path is a single owned subdirectory or manifest-swapped tree.
        let mut moved_next = Vec::new();
        for name in &self.next {
            if should_fail_before_new_rename(moved_next.len()) {
                return Err(self.rollback(
                    &backup_dir,
                    &moved_next,
                    &moved_previous,
                    Error::Config("injected staged export commit failure".to_string()),
                ));
            }
            if let Err(error) = fs::rename(self.stage_dir.join(name), self.output_dir.join(name)) {
                return Err(self.rollback(&backup_dir, &moved_next, &moved_previous, error.into()));
            }
            moved_next.push(name.clone());
        }

        let mut files: Vec<String> = self.next.iter().cloned().collect();
        files.sort();
        if let Err(error) =
            write_atomic(&self.output_dir.join(OWNERSHIP_FILE), &Ownership { files })
        {
            return Err(self.rollback(&backup_dir, &moved_next, &moved_previous, error));
        }

        // The manifest is the commit point. A failed best-effort cleanup only leaves
        // a private backup directory; it must not report a successful export as failed.
        let _ = fs::remove_dir_all(&self.stage_dir);
        Ok(())
    }

    fn sync_staged_files(&self) -> Result<(), Error> {
        for name in &self.next {
            let path = self.stage_dir.join(name);
            let file = fs::File::open(&path)?;
            file.sync_all()?;
        }
        Ok(())
    }

    fn rollback(
        &mut self,
        backup_dir: &Path,
        moved_next: &[String],
        moved_previous: &[String],
        original: Error,
    ) -> Error {
        let mut rollback_failures = Vec::new();
        for name in moved_next.iter().rev() {
            if let Err(error) = fs::rename(self.output_dir.join(name), self.stage_dir.join(name)) {
                rollback_failures.push(format!("restore staged {name}: {error}"));
            }
        }
        for name in moved_previous.iter().rev() {
            if let Err(error) = fs::rename(backup_dir.join(name), self.output_dir.join(name)) {
                rollback_failures.push(format!("restore previous {name}: {error}"));
            }
        }
        if rollback_failures.is_empty() {
            return original;
        }

        self.preserve_stage_on_drop = true;
        Error::Config(format!(
            "export commit failed ({original}); rollback was incomplete ({}) and recovery files were retained in {}",
            rollback_failures.join("; "),
            self.stage_dir.display()
        ))
    }
}

impl Drop for OutputStage {
    fn drop(&mut self) {
        if !self.preserve_stage_on_drop {
            let _ = fs::remove_dir_all(&self.stage_dir);
        }
    }
}

fn validated_names(
    files: impl IntoIterator<Item = String>,
    source: &str,
) -> Result<HashSet<String>, Error> {
    files
        .into_iter()
        .map(|name| match validate_generated_filename(&name) {
            Ok(()) => Ok(name),
            Err(reason) => Err(Error::Config(format!(
                "invalid {source} file name {name:?}: {reason}"
            ))),
        })
        .collect()
}

fn validate_generated_filename(name: &str) -> Result<(), &'static str> {
    let path = Path::new(name);
    if name.is_empty() || name.contains(['/', '\\']) {
        return Err("must be a single filename");
    }
    if !matches!(path.components().next(), Some(Component::Normal(_)))
        || path.components().count() != 1
    {
        return Err("must be a normal relative filename");
    }
    if name == OWNERSHIP_FILE || name.starts_with(".codehound-stage-") {
        return Err("uses a reserved CodeHound control filename");
    }
    Ok(())
}

#[cfg(test)]
fn should_fail_before_new_rename(moved_count: usize) -> bool {
    FAIL_AFTER_NEW_RENAMES.load(Ordering::Relaxed) == moved_count as u64
}

#[cfg(not(test))]
fn should_fail_before_new_rename(_: usize) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("codehound-{label}-{unique}"))
    }

    #[test]
    fn create_rejects_absolute_and_parent_manifest_names_without_touching_sentinels() {
        let root = unique_root("owned-manifest-path");
        let output_dir = root.join("output");
        let sentinel = root.join("sentinel.txt");
        fs::create_dir_all(&output_dir).expect("create output directory");
        fs::write(&sentinel, "do not delete").expect("write sentinel");

        for unsafe_name in [
            "../sentinel.txt".to_string(),
            sentinel.to_string_lossy().into_owned(),
        ] {
            let ownership = Ownership {
                files: vec![unsafe_name],
            };
            fs::write(
                output_dir.join(OWNERSHIP_FILE),
                serde_json::to_vec(&ownership).expect("serialize ownership"),
            )
            .expect("write ownership manifest");

            let result = OutputStage::create(&output_dir, ["1.txt".to_string()]);
            assert!(result.is_err(), "unsafe ownership name must be rejected");
            assert_eq!(
                fs::read_to_string(&sentinel).expect("read sentinel"),
                "do not delete"
            );
        }

        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn commit_restores_all_previous_files_when_a_later_new_file_move_fails() {
        let root = unique_root("owned-rollback");
        let output_dir = root.join("output");
        fs::create_dir_all(&output_dir).expect("create output directory");
        let ownership = Ownership {
            files: vec![
                "1.txt".to_string(),
                "2.txt".to_string(),
                "3.txt".to_string(),
            ],
        };
        fs::write(
            output_dir.join(OWNERSHIP_FILE),
            serde_json::to_vec(&ownership).expect("serialize ownership"),
        )
        .expect("write ownership manifest");
        for name in ["1.txt", "2.txt", "3.txt"] {
            fs::write(output_dir.join(name), format!("old {name}")).expect("write old output");
        }

        let stage = OutputStage::create(&output_dir, ["1.txt".to_string(), "2.txt".to_string()])
            .expect("create stage");
        fs::write(stage.path().join("1.txt"), "new 1").expect("write staged output");
        fs::write(stage.path().join("2.txt"), "new 2").expect("write staged output");
        FAIL_AFTER_NEW_RENAMES.store(1, Ordering::Relaxed);
        let result = stage.commit();
        FAIL_AFTER_NEW_RENAMES.store(u64::MAX, Ordering::Relaxed);

        assert!(result.is_err(), "injected commit failure must propagate");
        for name in ["1.txt", "2.txt", "3.txt"] {
            assert_eq!(
                fs::read_to_string(output_dir.join(name)).expect("read restored output"),
                format!("old {name}")
            );
        }
        let restored: Ownership = serde_json::from_slice(
            &fs::read(output_dir.join(OWNERSHIP_FILE)).expect("read ownership manifest"),
        )
        .expect("parse ownership manifest");
        assert_eq!(restored.files, ownership.files);

        fs::remove_dir_all(root).expect("remove test directory");
    }
}
