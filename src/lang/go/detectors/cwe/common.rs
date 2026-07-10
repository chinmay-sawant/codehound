use super::facts;
use super::source_index::SourceIndex;

pub fn is_configuration_sink(callee: &str) -> bool {
    crate::engine::sinks::CONFIG_SINKS.contains(callee)
}

pub fn is_path_traversal_sink(callee: &str) -> bool {
    crate::engine::sinks::PATH_TRAVERSAL_SINKS.contains(callee)
}

pub fn is_link_resolution_sink(callee: &str) -> bool {
    crate::engine::sinks::LINK_RESOLUTION_SINKS.contains(callee)
}

pub fn argument_uses_identifier(argument: &str, ident: &str) -> bool {
    argument == ident
        || argument
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|tok| tok == ident)
}

pub fn expression_uses_request_input(expr: &str) -> bool {
    expr.contains(".Query(")
        || expr.contains(".URL.Query().Get(")
        || expr.contains(".PostForm(")
        || expr.contains(".FormValue(")
        || expr.contains(".Param(")
        || expr.contains(".PathValue(")
}

pub fn is_path_confined(
    index: &SourceIndex,
    source: &str,
    assignment: &facts::AssignmentFact,
) -> bool {
    // filepath.Clean alone is NOT confinement — it does not root a path.
    // Accept: Base (final component only), or Abs/EvalSymlinks + HasPrefix on
    // the same binding (canonical + prefix guard).
    if assignment.expr.contains("filepath.Base(") {
        return true;
    }
    if assignment.expr.contains("filepath.Abs(")
        || assignment.expr.contains("filepath.EvalSymlinks(")
    {
        return has_canonical_path_guard(index, source, &assignment.name);
    }
    false
}

pub fn has_canonical_path_guard(index: &SourceIndex, source: &str, path_name: &str) -> bool {
    crate::engine::scratch_contains(source, "strings.HasPrefix(", path_name, ",")
        && index.has("filepath.Abs(")
}

pub fn has_symlink_guard(index: &SourceIndex, source: &str, path_name: &str) -> bool {
    crate::engine::scratch_contains(source, "os.Lstat(", path_name, ")")
        && index.has("os.ModeSymlink")
}
