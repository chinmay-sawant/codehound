//! Language-dispatched dependency extraction via [`LanguagePlugin::extract_deps`].

use std::path::Path;

use crate::core::{ParsedUnit, ProjectContext};
use crate::engine::path_identity::normalize_project_path;
use crate::engine::registry::Registry;

/// Extract project-local dependency paths for cache cascade.
///
/// Dispatches to the matching [`crate::core::LanguagePlugin::extract_deps`]
/// implementation so a new language does not need an engine `match` arm.
/// Language-specific module data (e.g. Go `module` path) is derived inside
/// the plugin from [`ProjectContext::root`].
pub fn extract_dependencies(unit: &ParsedUnit, project_root: &Path) -> Vec<String> {
    let registry = Registry::default();
    extract_dependencies_with_registry(&registry, unit, project_root)
}

/// Extract dependencies using the analyzer's already-built registry.
/// Avoids rebuilding every enabled language plugin for each scanned file.
///
/// Cache-key normalization (strip root, forward slashes, sort/dedup) stays here.
pub(crate) fn extract_dependencies_with_registry(
    registry: &Registry,
    unit: &ParsedUnit,
    project_root: &Path,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(plugin) = registry.plugin_for_id(unit.language) {
        let project = ProjectContext::new(project_root);
        out = plugin.extract_deps(unit, &project);
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
