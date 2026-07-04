//! Language-dispatched dependency extraction.

use std::path::Path;

use crate::core::{LanguageId, ParsedUnit};

use super::go_imports;
use super::python_imports;

/// File extensions scanned for each supported language.
pub(super) fn extensions_for(lang: LanguageId) -> &'static [&'static str] {
    match lang {
        LanguageId::Go => &["go"],
        LanguageId::Python => &["py"],
        #[cfg(feature = "typescript")]
        LanguageId::TypeScript => &["ts", "tsx", "js", "jsx"],
    }
}

/// Extract the list of project-local files that `unit` imports
/// (directly or, for Go directory imports, transitively at the
/// directory level).
///
/// `project_root` is used to resolve module-style imports to file
/// paths. The result is **absolute** paths, which lets the caller
/// store them in [`FileCacheMeta::dependencies`] and match them
/// directly against manifest keys (also absolute). `module_prefix`
/// is the Go module name read from `go.mod` (e.g.
/// `github.com/foo/bar`); it is the prefix that distinguishes local
/// imports from stdlib / third-party. `None` disables Go
/// dependency extraction — Python still works.
pub fn extract_dependencies(
    unit: &ParsedUnit,
    project_root: &Path,
    module_prefix: Option<&str>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    match unit.language {
        LanguageId::Go => {
            go_imports::extract(
                &unit.tree.root_node(),
                &unit.source,
                project_root,
                module_prefix.unwrap_or(""),
                &mut out,
            );
        }
        LanguageId::Python => {
            python_imports::extract(
                &unit.tree.root_node(),
                &unit.source,
                project_root,
                &unit.display_path,
                &mut out,
            );
        }
        #[cfg(feature = "typescript")]
        LanguageId::TypeScript => {}
    }
    out.sort();
    out.dedup();
    out
}

pub(super) use super::resolve::resolve_local_path;
pub(super) use extensions_for as extensions;
