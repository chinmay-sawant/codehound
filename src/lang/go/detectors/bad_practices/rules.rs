//! MVP bad-practice detectors.

use tree_sitter::Node;

use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

fn push_at(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    meta: &crate::rules::RuleMetadata,
    byte: usize,
    message: &str,
) {
    let (line, col) = unit.line_col(byte);
    emit::push_finding(meta, unit.display_path.as_str(), line, col, message, out);
}

fn line_start_byte(source: &str, line_no: usize) -> usize {
    let mut byte = 0;
    for (idx, line) in source.lines().enumerate() {
        if idx == line_no {
            return byte;
        }
        byte += line.len() + 1;
    }
    byte
}

/// BP-1: `_ = f()` where `f` likely returns an `error`.
pub(crate) fn detect_bp_1_discarded_error(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    fn walk(node: Node, src: &[u8], file: &str, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if node.kind() == "assignment_statement" || node.kind() == "short_var_declaration" {
            if let Ok(text) = node.utf8_text(src) {
                // Look for `_` on the LHS and a call on the RHS.
                if text.contains('_') && text.contains('(') && text.contains(')') {
                    let lhs = text
                        .split_once(":=")
                        .map(|(l, _)| l)
                        .or_else(|| text.split_once('=').map(|(l, _)| l));
                    if let Some(lhs) = lhs {
                        let names: Vec<&str> = lhs.split(',').map(str::trim).collect();
                        let discards_error = names.iter().any(|name| *name == "_")
                            && !names.iter().any(|name| name.eq_ignore_ascii_case("err"));
                        if discards_error {
                            let (line, col) = unit.line_col(node.start_byte());
                            emit::push_finding(
                                &crate::lang::go::detectors::bad_practices::BP_1_META,
                                file,
                                line,
                                col,
                                "discarded error return; handle or explicitly ignore with a comment",
                                out,
                            );
                        }
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, file, unit, out);
        }
    }

    walk(root, src, file, unit, out);
}

/// BP-2: `return err` without contextual wrapping.
pub(crate) fn detect_bp_2_naked_error_return(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    for (idx, line) in unit.source.lines().enumerate() {
        if line.trim() == "return err" {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_2_META,
                line_start_byte(unit.source.as_ref(), idx),
                "naked return err loses operation context; wrap it before returning",
            );
        }
    }
}

/// BP-3: `panic(...)` called outside `main()` or test files.
pub(crate) fn detect_bp_3_panic_outside_main(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    let is_test_file = file.ends_with("_test.go");
    let mut in_main = false;

    fn walk(
        node: Node,
        src: &[u8],
        file: &str,
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        is_test_file: bool,
        in_main: &mut bool,
    ) {
        if node.kind() == "function_declaration" {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
            {
                *in_main = name == "main";
            }
        }
        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(text) = func.utf8_text(src) {
                    if text == "panic" && !*in_main && !is_test_file {
                        let (line, col) = unit.line_col(node.start_byte());
                        emit::push_finding(
                            &crate::lang::go::detectors::bad_practices::BP_3_META,
                            file,
                            line,
                            col,
                            "panic outside main() or test files; prefer returning errors up the call stack",
                            out,
                        );
                    }
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, file, unit, out, is_test_file, in_main);
        }
    }

    walk(root, src, file, unit, out, is_test_file, &mut in_main);
}

/// BP-4: `recover()` without nearby logging or explicit reporting.
pub(crate) fn detect_bp_4_recover_without_logging(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !source.contains("recover()") {
        return;
    }
    let reports_recovery = source.contains("log.")
        || source.contains("Logger.")
        || source.contains(".Error(")
        || source.contains(".Warn(")
        || source.contains("fmt.Printf(")
        || source.contains("fmt.Fprintf(");
    if reports_recovery {
        return;
    }
    if let Some(pos) = source.find("recover()") {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_4_META,
            pos,
            "recover() suppresses panic information without logging or reporting it",
        );
    }
}

/// BP-5: Close() errors ignored through bare or deferred calls.
pub(crate) fn detect_bp_5_ignored_close_error(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if !trimmed.contains(".Close()") {
            continue;
        }
        let handled = trimmed.contains("if err :=")
            || trimmed.contains("if closeErr :=")
            || trimmed.contains("= ")
            || trimmed.starts_with("_ =");
        if !handled || trimmed.starts_with("defer ") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_5_META,
                line_start_byte(source, idx) + line.find(".Close()").unwrap_or(0),
                "Close() return value is ignored; check the close error where it can affect correctness",
            );
        }
    }
}

/// BP-6: sync.WaitGroup.Add inside the goroutine it tracks.
pub(crate) fn detect_bp_6_waitgroup_add_inside_goroutine(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
) {
    let source = unit.source.as_ref();
    if !source.contains("go func") || !source.contains(".Add(") {
        return;
    }
    let mut in_goroutine = false;
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("go func") || trimmed.contains("go func(") {
            in_goroutine = true;
        }
        if in_goroutine && trimmed.contains(".Add(") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_6_META,
                line_start_byte(source, idx) + line.find(".Add(").unwrap_or(0),
                "WaitGroup.Add is inside the goroutine; call Add before launching it",
            );
        }
        if in_goroutine && (trimmed == "}" || trimmed == "}()" || trimmed == "}()") {
            in_goroutine = false;
        }
    }
}

/// BP-7: sync.Mutex copied by function parameter value.
pub(crate) fn detect_bp_7_mutex_passed_by_value(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    for (idx, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("func ")
            && trimmed.contains(" sync.Mutex")
            && !trimmed.contains("*sync.Mutex")
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_7_META,
                line_start_byte(source, idx) + line.find("sync.Mutex").unwrap_or(0),
                "sync.Mutex is passed by value; pass *sync.Mutex to avoid copying lock state",
            );
        }
    }
}

/// BP-8: deferred unlock on a mutex value copy.
pub(crate) fn detect_bp_8_defer_unlock_on_mutex_copy(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !(source.contains(" sync.Mutex")
        && source.contains("defer ")
        && source.contains(".Unlock()"))
    {
        return;
    }
    for (idx, line) in source.lines().enumerate() {
        if line.trim().starts_with("defer ") && line.contains(".Unlock()") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_8_META,
                line_start_byte(source, idx) + line.find(".Unlock()").unwrap_or(0),
                "defer unlock is operating on a mutex value copy",
            );
        }
    }
}

/// BP-9: select without default, timeout, or context cancellation.
pub(crate) fn detect_bp_9_select_without_escape(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let Some(pos) = source.find("select {") else {
        return;
    };
    let block = &source[pos..source[pos..]
        .find('}')
        .map(|end| pos + end)
        .unwrap_or(source.len())];
    let has_escape = block.contains("default:")
        || block.contains("time.After(")
        || block.contains("time.NewTimer(")
        || block.contains("ctx.Done()")
        || block.contains("context.Done()")
        || block.contains("<-stop")
        || block.contains("<-done");
    if !has_escape {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_9_META,
            pos,
            "select can block indefinitely without default, timeout, or context cancellation",
        );
    }
}

/// BP-10: time.After inside a loop.
pub(crate) fn detect_bp_10_time_after_in_loop(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    fn is_loop(node: Node) -> bool {
        matches!(node.kind(), "for_statement" | "range_statement")
    }

    fn walk(node: Node, src: &[u8], unit: &ParsedUnit, out: &mut Vec<Finding>, inside_loop: bool) {
        let inside_loop = inside_loop || is_loop(node);
        if inside_loop && node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if func.utf8_text(src).ok() == Some("time.After") {
                    push_at(
                        unit,
                        out,
                        &crate::lang::go::detectors::bad_practices::BP_10_META,
                        node.start_byte(),
                        "time.After inside a loop allocates a new timer per iteration",
                    );
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, unit, out, inside_loop);
        }
    }

    walk(root, src, unit, out, false);
}

/// BP-11: `defer` inside a `for`/`range` loop body.
pub(crate) fn detect_bp_11_defer_in_loop(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();

    fn is_loop(node: Node) -> bool {
        matches!(
            node.kind(),
            "for_statement" | "range_statement" | "for_clause" | "range_clause"
        )
    }

    fn walk(
        node: Node,
        src: &[u8],
        file: &str,
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        inside_loop: bool,
    ) {
        let inside_loop = inside_loop || is_loop(node);
        if inside_loop && node.kind() == "defer_statement" {
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &crate::lang::go::detectors::bad_practices::BP_11_META,
                file,
                line,
                col,
                "defer inside a loop defers cleanup until the surrounding function returns",
                out,
            );
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, file, unit, out, inside_loop);
        }
    }

    walk(root, src, file, unit, out, false);
}

/// BP-13: context.Background used outside main/test code.
pub(crate) fn detect_bp_13_background_context_in_library(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
) {
    let file = unit.display_path.as_str();
    if file.ends_with("_test.go") {
        return;
    }
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut function_stack: Vec<String> = Vec::new();

    fn walk(
        node: Node,
        src: &[u8],
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        function_stack: &mut Vec<String>,
    ) {
        let pushed = if node.kind() == "function_declaration" {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
            {
                function_stack.push(name.to_string());
                true
            } else {
                false
            }
        } else {
            false
        };

        if node.kind() == "call_expression" {
            if let Some(func) = node.child_by_field_name("function") {
                if func.utf8_text(src).ok() == Some("context.Background")
                    && function_stack
                        .last()
                        .is_some_and(|name| name != "main" && name != "init")
                {
                    push_at(
                        unit,
                        out,
                        &crate::lang::go::detectors::bad_practices::BP_13_META,
                        node.start_byte(),
                        "context.Background used in library code; accept and propagate a caller context",
                    );
                }
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, unit, out, function_stack);
        }
        if pushed {
            function_stack.pop();
        }
    }

    walk(root, src, unit, out, &mut function_stack);
}

/// BP-15: sync.Once.Do recursively calls the same Once.
pub(crate) fn detect_bp_15_recursive_once_do(unit: &ParsedUnit, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let Some(do_pos) = source.find(".Do(func()") else {
        return;
    };
    let prefix = &source[..do_pos];
    let once_name = prefix
        .rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()
        .unwrap_or("");
    if once_name.is_empty() {
        return;
    }
    let body = &source[do_pos..];
    let recursive_call = format!("{once_name}.Do(");
    if body.contains(&recursive_call) {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_15_META,
            do_pos,
            "sync.Once.Do closure recursively calls the same Once",
        );
    }
}
