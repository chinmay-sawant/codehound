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

/// Returns true if the source file shows evidence of a request handler
/// (Gin / Echo / net/http). Used to decide whether a call is on the hot path.
pub fn is_request_path(source: &str) -> bool {
    source.contains("gin.HandlerFunc")
        || source.contains("echo.HandlerFunc")
        || source.contains("http.HandlerFunc")
        || source.contains("func Handle")
        || source.contains("func ServeHTTP")
        || source.contains("c.JSON(")
        || source.contains("c.String(")
        || source.contains("c.HTML(")
        || source.contains("c.Bind(")
        || source.contains("c.ShouldBind")
        || has_gin_handler(source)
        || has_echo_handler(source)
        || has_http_handler(source)
        || source.contains("func (")
}

/// `func Xxx(c *gin.Context) { ... }` — Gin handlers with a `*gin.Context`
/// receiver or parameter are the canonical Gin handler shape.
pub fn has_gin_handler(source: &str) -> bool {
    source.contains("*gin.Context")
}

/// `func Xxx(c echo.Context) { ... }` — Echo handlers take the context as a
/// parameter rather than a receiver.
pub fn has_echo_handler(source: &str) -> bool {
    source.contains("echo.Context")
}

/// `func Xxx(w http.ResponseWriter, r *http.Request)` — net/http handlers.
pub fn has_http_handler(source: &str) -> bool {
    source.contains("http.ResponseWriter")
}
