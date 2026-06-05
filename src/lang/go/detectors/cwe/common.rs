use super::facts;

pub(super) fn is_configuration_sink(callee: &str) -> bool {
    matches!(callee, "sql.Open" | "factory")
}

pub(super) fn is_path_traversal_sink(callee: &str) -> bool {
    matches!(callee, "os.ReadFile")
}

pub(super) fn is_link_resolution_sink(callee: &str) -> bool {
    matches!(callee, "os.Open" | "os.OpenFile")
}

pub(super) fn argument_uses_identifier(argument: &str, ident: &str) -> bool {
    argument == ident
}

pub(super) fn expression_uses_request_input(expr: &str) -> bool {
    expr.contains(".Query(")
        || expr.contains(".URL.Query().Get(")
        || expr.contains(".PostForm(")
        || expr.contains(".FormValue(")
        || expr.contains(".Param(")
        || expr.contains(".PathValue(")
}

pub(super) fn is_path_confined(source: &str, assignment: &facts::AssignmentFact) -> bool {
    (assignment.expr.contains("filepath.Clean(")
        && crate::engine::scratch_contains(
            source,
            "strings.HasPrefix(",
            &assignment.name,
            ",",
        ))
        || assignment.expr.contains("filepath.Base(")
        || (assignment.expr.contains("filepath.Abs(")
            && has_canonical_path_guard(source, &assignment.name))
}

pub(super) fn has_canonical_path_guard(source: &str, path_name: &str) -> bool {
    crate::engine::scratch_contains(source, "strings.HasPrefix(", path_name, ",")
        && source.contains("filepath.Abs(")
}

pub(super) fn has_symlink_guard(source: &str, path_name: &str) -> bool {
    crate::engine::scratch_contains(source, "os.Lstat(", path_name, ")")
        && source.contains("os.ModeSymlink")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_canonical_path_guard_matches_known_pattern() {
        let src = r#"if strings.HasPrefix(p, "/safe/") { filepath.Abs(p) }"#;
        assert!(has_canonical_path_guard(src, "p"));
    }

    #[test]
    fn has_symlink_guard_matches_known_pattern() {
        let src = r#"if os.Lstat(p) && os.ModeSymlink { return }"#;
        assert!(has_symlink_guard(src, "p"));
    }

    #[test]
    fn is_path_confined_recognises_filepath_clean() {
        let a = facts::AssignmentFact {
            name: "p".to_string(),
            expr: r#"filepath.Clean(p)"#.to_string(),
            start_byte: 0,
        };
        let src = r#"if strings.HasPrefix(p, "/safe/") { return p }"#;
        assert!(is_path_confined(src, &a));
    }
}
