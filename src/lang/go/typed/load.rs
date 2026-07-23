//! Load package identity via `go list -json` (toolchain required).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use serde::Deserialize;

use super::session::TypedFacts;

/// Outcome of an optional typed/package-graph load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedLoadStatus {
    /// `--typed` off or session not installed.
    Off,
    /// Typed requested but toolchain/load failed; tree-sitter continues.
    Unavailable(String),
    /// At least one package file was indexed.
    Ready {
        /// Packages returned by `go list` with files.
        packages: usize,
        /// Go source files indexed to import paths.
        files: usize,
        /// Wall time for the load in milliseconds.
        wall_ms: u128,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListPackage {
    dir: Option<String>,
    import_path: Option<String>,
    go_files: Option<Vec<String>>,
    #[serde(default)]
    error: Option<GoListError>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoListError {
    /// Present when the package failed to load; we only need presence.
    #[serde(default)]
    #[allow(dead_code)]
    err: Option<String>,
}

/// Load facts for `root` into `facts` (merge). Returns final status for this root.
pub fn load_project_facts(root: &Path, facts: &TypedFacts) -> TypedLoadStatus {
    load_into(facts, root);
    facts.status()
}

pub(super) fn load_into(facts: &TypedFacts, root: &Path) {
    let t0 = Instant::now();
    let go = which_go();
    let Some(go) = go else {
        let msg = "go toolchain not found on PATH (typed mode requires Go)".to_string();
        tracing::warn!(%msg, "typed load degraded");
        facts.set_status(TypedLoadStatus::Unavailable(msg));
        return;
    };

    let output = Command::new(&go)
        .args(["list", "-json", "-e", "./..."])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();

    let output = match output {
        Ok(o) => o,
        Err(e) => {
            let msg = format!("failed to spawn go list: {e}");
            tracing::warn!(%msg, "typed load degraded");
            facts.set_status(TypedLoadStatus::Unavailable(msg));
            return;
        }
    };

    if !output.status.success() && output.stdout.is_empty() {
        let err = String::from_utf8_lossy(&output.stderr);
        let msg = format!(
            "go list failed (exit {:?}): {}",
            output.status.code(),
            err.trim()
        );
        tracing::warn!(%msg, root = %root.display(), "typed load degraded");
        facts.set_status(TypedLoadStatus::Unavailable(msg));
        return;
    }

    let mut packages = 0usize;
    let mut files = 0usize;
    for pkg in parse_go_list_stream(&output.stdout) {
        if pkg.error.is_some() && pkg.go_files.as_ref().map(|g| g.is_empty()).unwrap_or(true) {
            continue;
        }
        let Some(dir) = pkg.dir.as_deref() else {
            continue;
        };
        let Some(import_path) = pkg.import_path.clone() else {
            continue;
        };
        packages += 1;
        let dir_path = PathBuf::from(dir);
        for name in pkg.go_files.unwrap_or_default() {
            let file = dir_path.join(&name);
            let key = file.canonicalize().unwrap_or(file);
            facts.insert_file(key, import_path.clone());
            files += 1;
        }
    }

    let wall_ms = t0.elapsed().as_millis();
    if files == 0 {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let msg = if stderr.trim().is_empty() {
            "go list returned no Go files".to_string()
        } else {
            format!("go list produced no files: {}", stderr.trim())
        };
        tracing::warn!(%msg, root = %root.display(), "typed load degraded");
        facts.set_status(TypedLoadStatus::Unavailable(msg));
        return;
    }

    tracing::info!(
        root = %root.display(),
        packages,
        files,
        wall_ms,
        "typed package facts loaded via go list"
    );
    facts.set_status(TypedLoadStatus::Ready {
        packages,
        files,
        wall_ms,
    });
}

fn which_go() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CODEHOUND_GO") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    // Common locations + PATH.
    for candidate in ["/usr/local/go/bin/go", "/usr/bin/go", "/usr/lib/go/bin/go"] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join("go");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// `go list -json` emits concatenated JSON objects (not a JSON array).
fn parse_go_list_stream(bytes: &[u8]) -> Vec<GoListPackage> {
    let mut out = Vec::new();
    let dec = serde_json::Deserializer::from_slice(bytes).into_iter::<GoListPackage>();
    for item in dec {
        match item {
            Ok(pkg) => out.push(pkg),
            Err(_) => break,
        }
    }
    // Fallback: if stream parse got nothing, try whole-buffer single object.
    if out.is_empty() && !bytes.is_empty() {
        if let Ok(pkg) = serde_json::from_slice::<GoListPackage>(bytes) {
            out.push(pkg);
        }
    }
    out
}
