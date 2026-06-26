use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use slopguard::rules::{Finding, LineCol, Severity};

pub fn unique_temp_root(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("slopguard-{test_name}-{unique}"))
}

pub fn write_minimal_go(path: &Path) {
    std::fs::write(
        path,
        r#"package sample

import (
	"net/http"
	"os/exec"
)

func Run(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	_, _ = cmd.CombinedOutput()
}
"#,
    )
    .unwrap();
}

pub fn finding(rule_id: &'static str, file: &str, line: usize, column: usize) -> Finding {
    Finding::new(
        rule_id,
        "title",
        file,
        LineCol { line, column },
        "msg",
        Severity::High,
        Cow::Borrowed(&[]),
    )
}

#[cfg(feature = "go")]
pub mod dep_helpers {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use slopguard::core::LanguagePlugin;
    use slopguard::engine::{extract_dependencies, go_module_prefix};
    use slopguard::lang::go::GoPlugin;

    pub fn unique_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("slopguard-dep-{label}-{unique}"))
    }

    pub fn write_file(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    pub fn parse_go(project: &Path, rel: &str) -> (slopguard::core::ParsedUnit, Option<String>) {
        let path = project.join(rel);
        let source = std::fs::read_to_string(&path).unwrap();
        let plugin = GoPlugin;
        let mut parser = tree_sitter::Parser::new();
        plugin.configure_parser(&mut parser);
        let unit = plugin
            .parse_with(&mut parser, &path, Arc::from(source.as_str()))
            .unwrap();
        let module = go_module_prefix(project);
        (unit, module)
    }

    pub fn deps_for(project: &Path, rel: &str) -> Vec<String> {
        let (unit, module) = parse_go(project, rel);
        extract_dependencies(&unit, project, module.as_deref())
    }
}
