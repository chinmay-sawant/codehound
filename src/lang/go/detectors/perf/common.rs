//! Shared helpers for the Go PERF detector bundle.

use super::facts::{AssignmentFact, CallFact};

/// True if the call site has an enclosing `for_statement`.
pub fn is_in_loop(call: &CallFact) -> bool {
    call.enclosing_loop.is_some()
}

/// True if the assignment site has an enclosing `for_statement`.
pub fn is_assignment_in_loop(assignment: &AssignmentFact) -> bool {
    assignment.enclosing_loop.is_some()
}

/// Returns true if any argument of a call looks like a regexp compile invocation.
pub fn is_regexp_compile(callee: &str) -> bool {
    matches!(callee, "regexp.MustCompile" | "regexp.Compile")
}

/// Returns true if the call site lives in a request-handler shape
/// (handler, middleware, or explicit HTTP entrypoint). Used to flag
/// per-request parsing that should be hoisted out of the hot path.
pub fn is_request_path(source: &str) -> bool {
    source.contains("func (")
        || source.contains("gin.HandlerFunc")
        || source.contains("echo.HandlerFunc")
        || source.contains("http.HandlerFunc")
        || source.contains("func Handle")
        || source.contains("func ServeHTTP")
        || source.contains("c.JSON(")
        || source.contains("c.String(")
        || source.contains("c.HTML(")
        || source.contains("c.Render(")
        || source.contains("c.Bind(")
        || source.contains("c.ShouldBind")
}
