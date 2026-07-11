//! Project-relative path identity for cache keys, dependency lists, and findings.
//!
//! All cache/manifest/dep strings use the same normal form so cascade
//! invalidation does not miss on `\` vs `/` or `./` prefixes.

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
}
