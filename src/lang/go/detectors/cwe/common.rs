use super::facts;

pub fn is_configuration_sink(callee: &str) -> bool {
    matches!(callee, "sql.Open" | "factory")
}

pub fn is_path_traversal_sink(callee: &str) -> bool {
    matches!(callee, "os.ReadFile")
}

pub fn is_link_resolution_sink(callee: &str) -> bool {
    matches!(callee, "os.Open" | "os.OpenFile")
}

pub fn argument_uses_identifier(argument: &str, ident: &str) -> bool {
    argument == ident
}

pub fn expression_uses_request_input(expr: &str) -> bool {
    expr.contains(".Query(")
        || expr.contains(".URL.Query().Get(")
        || expr.contains(".PostForm(")
        || expr.contains(".FormValue(")
        || expr.contains(".Param(")
        || expr.contains(".PathValue(")
}

pub fn is_path_confined(source: &str, assignment: &facts::AssignmentFact) -> bool {
    (assignment.expr.contains("filepath.Clean(")
        && crate::engine::scratch_contains(source, "strings.HasPrefix(", &assignment.name, ","))
        || assignment.expr.contains("filepath.Base(")
        || (assignment.expr.contains("filepath.Abs(")
            && has_canonical_path_guard(source, &assignment.name))
}

pub fn has_canonical_path_guard(source: &str, path_name: &str) -> bool {
    crate::engine::scratch_contains(source, "strings.HasPrefix(", path_name, ",")
        && source.contains("filepath.Abs(")
}

pub fn has_symlink_guard(source: &str, path_name: &str) -> bool {
    crate::engine::scratch_contains(source, "os.Lstat(", path_name, ")")
        && source.contains("os.ModeSymlink")
}
