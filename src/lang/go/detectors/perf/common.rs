//! Shared helpers for the Go PERF detector bundle.

use super::source_index::PerfSourceIndex;

/// Clamp `index` to the nearest valid UTF-8 char boundary ≤ index.
/// MSRV-safe equivalent of `str::floor_char_boundary` (stable 1.91).
pub(crate) fn char_boundary(s: &str, mut index: usize) -> usize {
    let len = s.len();
    if index > len {
        index = len;
    }
    while !s.is_char_boundary(index) {
        index -= 1;
    }
    index
}

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
pub fn is_request_path(index: &PerfSourceIndex) -> bool {
    index.has("gin.HandlerFunc")
        || index.has("echo.HandlerFunc")
        || index.has("http.HandlerFunc")
        || index.has("func Handle")
        || index.has("func ServeHTTP")
        || index.has("c.JSON(")
        || index.has("c.String(")
        || index.has("c.HTML(")
        || index.has("c.Bind(")
        || index.has("c.ShouldBind")
        || has_gin_handler(index)
        || has_echo_handler(index)
        || has_http_handler(index)
        || index.has("func (")
}

/// `func Xxx(c *gin.Context) { ... }` — Gin handlers with a `*gin.Context`
/// receiver or parameter are the canonical Gin handler shape.
pub fn has_gin_handler(index: &PerfSourceIndex) -> bool {
    index.has("*gin.Context")
}

/// `func Xxx(c echo.Context) { ... }` — Echo handlers take the context as a
/// parameter rather than a receiver.
pub fn has_echo_handler(index: &PerfSourceIndex) -> bool {
    index.has("echo.Context")
}

/// `func Xxx(w http.ResponseWriter, r *http.Request)` — net/http handlers.
pub fn has_http_handler(index: &PerfSourceIndex) -> bool {
    index.has("http.ResponseWriter")
}

/// Returns true if the 1 KiB window before `start_byte` contains a
/// request-handler signature token (http.ResponseWriter, gin.Context,
/// echo.Context, fiber.Ctx, or common response methods).
pub fn is_handler_shaped(source: &str, start_byte: usize) -> bool {
    let window_start = char_boundary(source, start_byte.saturating_sub(1024));
    let window = &source[window_start..start_byte];
    window.contains("http.ResponseWriter")
        || window.contains("*gin.Context")
        || window.contains("gin.Context")
        || window.contains("echo.Context")
        || window.contains("c echo.Context")
        || window.contains("*fiber.Ctx")
        || window.contains("c *fiber.Ctx")
        || window.contains("func Handle")
        || window.contains("func (")
        || window.contains("c.JSON(")
        || window.contains("c.String(")
        || window.contains("c.HTML(")
}

/// Whole-file handler-shape check: returns true when the file contains
/// a request-handler signature token anywhere.
pub fn file_has_handler(source: &str) -> bool {
    is_handler_shaped(source, source.len())
}
