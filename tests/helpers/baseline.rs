use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq)]
pub struct FindingStub {
    pub rule_id: String,
    pub file: String,
}

pub struct TempProject {
    root: PathBuf,
}

impl TempProject {
    pub fn new(test_name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("slopguard-{test_name}-{unique}"));
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn join(&self, path: impl AsRef<Path>) -> PathBuf {
        self.root.join(path)
    }

    pub fn write_file(&self, path: impl AsRef<Path>, contents: impl AsRef<[u8]>) {
        let path = self.root.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    pub fn write_python_finding(&self, path: impl AsRef<Path>) {
        self.write_file(
            path,
            "import re\n\nfor item in items:\n    re.compile(item)\n",
        );
    }
}

impl Drop for TempProject {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub fn setup_temp_project(fixtures: &[&str]) -> TempProject {
    let project = TempProject::new("baseline");
    for fixture in fixtures {
        project.write_python_finding(fixture);
    }
    project
}

pub fn run_slopguard(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_slopguard"))
        .current_dir(cwd)
        .args(args)
        .output()
        .unwrap()
}

pub fn parse_findings(output: &str) -> Vec<FindingStub> {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .map(|value| FindingStub {
            rule_id: value["rule_id"].as_str().unwrap_or_default().to_string(),
            file: value["file"].as_str().unwrap_or_default().to_string(),
        })
        .collect()
}

pub fn save_baseline(project: &TempProject, source_path: &str, baseline_path: &str) {
    let args = [
        "--baseline",
        "--baseline-file",
        baseline_path,
        "--no-context",
        "--no-chunks",
        "--lang",
        "python",
        source_path,
    ];
    let save = run_slopguard(&args, project.path());

    assert!(
        save.status.success(),
        "save failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&save.stdout),
        String::from_utf8_lossy(&save.stderr)
    );
}
