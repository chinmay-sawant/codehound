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

/// Function-name tokens that usually mark encode / emit / serve hot paths
/// (libraries and services alike — not HTTP-only).
const HOT_FUNCTION_TOKENS: &[&str] = &[
    "handle",
    "serve",
    "write",
    "encode",
    "decode",
    "build",
    "generate",
    "render",
    "compress",
    "sign",
    "marshal",
    "unmarshal",
    "emit",
    "serialize",
    "deserialize",
    "process",
    "transform",
    "flush",
    "draw",
    "layout",
];

/// True when `name` looks like a hot-path function (case-insensitive substring).
pub fn function_name_is_hot(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    HOT_FUNCTION_TOKENS.iter().any(|tok| lower.contains(tok))
}

/// Walk backward from `start_byte` to the nearest `func` declaration and
/// return its simple name (`Foo` from `func Foo` / `func (r *T) Foo`).
///
/// Returns `None` when `start_byte` is not inside that function body (e.g.
/// package-level `var x = build()` between top-level decls).
pub fn enclosing_function_name(source: &str, start_byte: usize) -> Option<&str> {
    let start_byte = start_byte.min(source.len());
    let head = &source[..start_byte];
    let func_kw = head.rfind("func ")?;
    let after_kw = &source[func_kw + "func ".len()..start_byte];
    let after = after_kw.trim_start();
    // Method: (recv Type) Name
    let after = if after.starts_with('(') {
        let close = after.find(')')?;
        after[close + 1..].trim_start()
    } else {
        after
    };
    let name_end = after
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(after.len());
    let name = &after[..name_end];
    if name.is_empty() {
        return None;
    }

    // Ensure start_byte is still inside this function body: open `{` after the
    // func keyword and brace-depth at start_byte remains positive.
    let Some(brace_rel) = source[func_kw..start_byte].find('{') else {
        return None;
    };
    let body_open = func_kw + brace_rel;
    let mut depth = 0i32;
    for ch in source[body_open..start_byte].chars() {
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            _ => {}
        }
    }
    if depth <= 0 {
        return None;
    }
    Some(name)
}

/// True when the nearest enclosing function name looks hot.
pub fn enclosing_function_is_hot(source: &str, start_byte: usize) -> bool {
    enclosing_function_name(source, start_byte)
        .map(function_name_is_hot)
        .unwrap_or(false)
}

/// Unified hot-path predicate for enhanced PERF matching.
///
/// A site is hot when any of:
/// - it sits inside a loop
/// - the **local** window is handler-shaped (not whole-file — package init
///   in a handler file must stay cold)
/// - the enclosing function name matches encode/serve/build-style tokens
///
/// Whole-file `is_request_path` is intentionally **not** used here: it would
/// mark every call in a handler-containing file as hot (including package
/// `var x = build()` init sites).
pub fn is_hot_path(
    source: &str,
    start_byte: usize,
    _index: &PerfSourceIndex,
    in_loop: bool,
) -> bool {
    if in_loop {
        return true;
    }
    if is_handler_shaped(source, start_byte) {
        return true;
    }
    enclosing_function_is_hot(source, start_byte)
}

/// True when the file as a whole looks concurrent (goroutine fan-out).
pub fn file_has_concurrency(source: &str) -> bool {
    source.contains("go ")
        || source.contains("go\t")
        || source.contains("go\n")
        || source.contains("errgroup")
        || source.contains("WaitGroup")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_name_is_hot_matches_common_tokens() {
        assert!(function_name_is_hot("GenerateDoc"));
        assert!(function_name_is_hot("encodePage"));
        assert!(function_name_is_hot("SignPDF"));
        assert!(!function_name_is_hot("init"));
        assert!(!function_name_is_hot("helper"));
    }

    #[test]
    fn enclosing_function_name_finds_plain_and_method() {
        let src = "package p\nfunc GenerateDoc() {\n\tx := 1\n}\n";
        let byte = src.find("x :=").unwrap();
        assert_eq!(enclosing_function_name(src, byte), Some("GenerateDoc"));

        let src = "package p\nfunc (g *Gen) Encode() {\n\ty := 2\n}\n";
        let byte = src.find("y :=").unwrap();
        assert_eq!(enclosing_function_name(src, byte), Some("Encode"));
    }

    #[test]
    fn enclosing_function_name_ignores_package_level_between_funcs() {
        let src = "package p\nfunc buildX() []byte { return nil }\nvar x = buildX()\nfunc Handle() {}\n";
        // First occurrence is the func name itself; use the package var call.
        let byte = src.rfind("buildX()").unwrap();
        assert_eq!(enclosing_function_name(src, byte), None);
    }
}
