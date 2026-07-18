//! Project-relative path identity for cache keys, dependency lists, and findings.
//!
//! All cache/manifest/dep strings use the same normal form so cascade
//! invalidation does not miss on `\` vs `/` or `./` prefixes.

/// Path components treated as example/demo trees (Go ecosystem conventions).
///
/// Used to label findings, not to suppress them by default.
pub const EXAMPLE_PATH_COMPONENTS: &[&str] = &["examples", "example", "sampledata", "samples"];

/// Tag attached to findings whose file path lives under an example/demo tree.
pub const EXAMPLE_FINDING_TAG: &str = "example";

/// Gitignore-style globs for optional `--exclude-examples` discovery filtering.
pub const EXAMPLE_EXCLUDE_GLOBS: &[&str] = &[
    "**/examples/**",
    "**/example/**",
    "**/sampledata/**",
    "**/samples/**",
];

/// Normalize a project-relative path for cache and dependency identity.
///
/// Rules:
/// - Backslashes → forward slashes
/// - Strip a single leading `./`
/// - Collapse repeated `/` (except leave empty as empty)
///
/// Does **not** resolve `..` (paths are expected already project-relative).
#[must_use]
pub fn normalize_project_path(path: &str) -> String {
    let mut s = path.replace('\\', "/");
    // Collapse // first so `.//pkg` becomes `./pkg` before stripping.
    while s.contains("//") {
        s = s.replace("//", "/");
    }
    while s.starts_with("./") {
        s = s[2..].to_string();
    }
    s
}

/// True if two project paths refer to the same identity after normalization.
#[must_use]
pub fn project_paths_eq(a: &str, b: &str) -> bool {
    normalize_project_path(a) == normalize_project_path(b)
}

/// True when a path component is an example/demo directory name.
///
/// Matches whole components only (`examples/foo.go`, not `myexamples/foo.go`
/// or `example.go`).
#[must_use]
pub fn is_example_demo_path(path: &str) -> bool {
    normalize_project_path(path)
        .split('/')
        .any(|component| EXAMPLE_PATH_COMPONENTS.contains(&component))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_separators_and_dot_slash() {
        assert_eq!(normalize_project_path(r"a\b\c.go"), "a/b/c.go");
        assert_eq!(normalize_project_path("./pkg/x.go"), "pkg/x.go");
        assert_eq!(normalize_project_path(".//pkg//x.go"), "pkg/x.go");
    }

    #[test]
    fn equality_is_normalization_aware() {
        assert!(project_paths_eq(r"pkg\db.go", "pkg/db.go"));
        assert!(project_paths_eq("./pkg/db.go", "pkg/db.go"));
        assert!(!project_paths_eq("pkg/a.go", "pkg/b.go"));
    }

    #[test]
    fn example_demo_path_matches_known_components() {
        assert!(is_example_demo_path("examples/basic/main.go"));
        assert!(is_example_demo_path("./example/demo.go"));
        assert!(is_example_demo_path(r"sampledata\bench\gen.go"));
        assert!(is_example_demo_path("pkg/samples/x.go"));
        assert!(!is_example_demo_path("pkg/example.go"));
        assert!(!is_example_demo_path("myexamples/x.go"));
        assert!(!is_example_demo_path("internal/storage/redis.go"));
    }
}
