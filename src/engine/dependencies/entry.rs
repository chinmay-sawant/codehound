//! Language-dispatched dependency extraction via [`LanguagePlugin::extract_deps`].

use std::path::Path;

use crate::core::ParsedUnit;
use crate::engine::path_identity::normalize_project_path;
use crate::lang::enabled_plugins;

/// Extract project-local dependency paths for cache cascade.
///
/// Dispatches to the matching [`crate::core::LanguagePlugin::extract_deps`]
/// implementation so a new language does not need an engine `match` arm.
pub fn extract_dependencies(
    unit: &ParsedUnit,
    project_root: &Path,
    module_prefix: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    for plugin in enabled_plugins() {
        if plugin.id() == unit.language {
            out = plugin.extract_deps(unit, project_root, module_prefix);
            break;
        }
    }
    for path in &mut out {
        let as_path = Path::new(path.as_str());
        if let Ok(rel) = as_path.strip_prefix(project_root) {
            *path = normalize_project_path(&rel.to_string_lossy());
        } else {
            *path = normalize_project_path(path);
        }
    }
    out.sort();
    out.dedup();
    out
}
