//! Parse the `module` directive from a `go.mod` file.

use std::fs;
use std::path::Path;

pub fn go_module_prefix(project_root: &Path) -> Option<String> {
    let path = project_root.join("go.mod");
    let text = fs::read_to_string(&path).ok()?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("module ") {
            let name = rest.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}
