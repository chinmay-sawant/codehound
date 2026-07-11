//! Dependency extraction for the incremental analysis cache (P2.3
//! Phase 3.2). The cache stores per-file `dependencies: Vec<String>`
//! so that an edit to an upstream file can invalidate every
//! downstream cache entry.
//!
//! Two strategies are implemented:
//!
//! - **Go** ([`go_imports`]): every `import_spec` whose path begins with the
//!   project module prefix (e.g. `github.com/foo/bar`) is mapped to a
//!   local path. If the path resolves to a `.go` file, that file is a
//!   dependency. If it resolves to a directory, **every** `.go` file
//!   in that directory is a dependency. Stdlib and third-party imports
//!   are skipped — they never invalidate.
//! - **Python** ([`python_imports`]): every `import_statement` /
//!   `import_from_statement` is mapped to a `.py` file (or
//!   `__init__.py` for packages) when it can be resolved to a path
//!   inside the project. Relative imports are resolved against the
//!   source file's package directory.
//!
//! Only local file paths are returned; external modules are dropped
//! because they are immutable from the project's perspective and so
//! would never trigger a cache invalidation.
//!
//! Both functions return paths **relative to `project_root`**, using
//! [`normalize_project_path`](crate::engine::normalize_project_path)
//! (forward slashes, no `./`), so reverse-dep cascade matches manifest
//! keys and `display_path` used by [`crate::engine::walk`].

mod entry;
mod go_imports;
mod go_module;
mod project_root;
mod python_imports;
mod resolve;
#[cfg(test)]
mod tests;

pub use entry::extract_dependencies;
pub use go_module::go_module_prefix;
pub use project_root::discover_project_root;
