//! BP-16..BP-25 — test-only bad practices.

use tree_sitter::Node;

use super::super::common::is_test_file;
use super::super::source_index::SourceIndex;
use super::helpers::{line_start_byte, push_at};
use crate::core::ParsedUnit;
use crate::rules::Finding;

pub(crate) fn detect_bp_16_time_sleep_in_test(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    walk_call_expressions(unit, out, |node, src, unit, out| {
        if call_name(node, src) == Some("time.Sleep") && !has_loop_ancestor(node) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_16_META,
                node.start_byte(),
                "time.Sleep in a test is brittle; prefer deterministic synchronization",
            );
        }
    });
}

pub(crate) fn detect_bp_17_t_error_followed_by_t_fatal(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    let source = unit.source.as_ref();
    let lines: Vec<&str> = source.lines().collect();
    for idx in 0..lines.len().saturating_sub(1) {
        let current = lines[idx].trim();
        let next = lines[idx + 1].trim();
        if matches!(current, c if c.starts_with("t.Error(") || c.starts_with("t.Errorf("))
            && matches!(next, n if n.starts_with("t.Fatal(") || n.starts_with("t.Fatalf("))
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_17_META,
                line_start_byte(source, idx),
                "t.Error immediately followed by t.Fatal is redundant; fail once with t.Fatal",
            );
        }
    }
}

pub(crate) fn detect_bp_18_t_error_without_early_exit(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    let source = unit.source.as_ref();
    let lines: Vec<&str> = source.lines().collect();
    for idx in 0..lines.len().saturating_sub(1) {
        let current = lines[idx].trim();
        if !(current.starts_with("t.Error(") || current.starts_with("t.Errorf(")) {
            continue;
        }
        let mut next_idx = idx + 1;
        while next_idx < lines.len() && lines[next_idx].trim().is_empty() {
            next_idx += 1;
        }
        let Some(next) = lines.get(next_idx).map(|line| line.trim()) else {
            continue;
        };
        let terminates = next == "return"
            || next.starts_with("t.FailNow(")
            || next.starts_with("t.Fatal(")
            || next.starts_with("t.Fatalf(")
            || next.starts_with("t.Skip(")
            || next.starts_with("t.Skipf(")
            || next.starts_with("t.SkipNow(");
        if !terminates {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_18_META,
                line_start_byte(source, idx),
                "t.Error continues the test path; return or fail immediately after the error",
            );
        }
    }
}

pub(crate) fn detect_bp_19_missing_t_helper_on_test_helper(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    walk_functions(unit, out, |function, src, unit, out| {
        let Some(name) = function_name(function, src) else {
            return;
        };
        if !looks_like_test_helper(name, function, src) {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let has_helper_first = body
            .utf8_text(src)
            .ok()
            .and_then(first_non_empty_body_line)
            .is_some_and(|line| line.starts_with("t.Helper("));
        if !has_helper_first {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_19_META,
                function.start_byte(),
                "test helper should call t.Helper() first so failures point at the caller",
            );
        }
    });
}

pub(crate) fn detect_bp_20_table_test_without_t_run(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    walk_functions(unit, out, |function, src, unit, out| {
        if !is_test_function(function, src) {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        if (contains_kind(body, "range_statement") || contains_kind(body, "for_statement"))
            && !contains_call(body, src, "t.Run")
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_20_META,
                function.start_byte(),
                "table-driven test loops should use t.Run for named subtests",
            );
        }
    });
}

pub(crate) fn detect_bp_21_subtest_missing_t_parallel(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    walk_call_expressions(unit, out, |node, src, unit, out| {
        if call_name(node, src) != Some("t.Run") {
            return;
        }
        let Some(arguments) = node.child_by_field_name("arguments") else {
            return;
        };
        let mut cursor = arguments.walk();
        for child in arguments.named_children(&mut cursor) {
            if child.kind() == "func_literal"
                && !contains_call(child, src, "t.Parallel")
                && has_loop_ancestor(node)
            {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_21_META,
                    node.start_byte(),
                    "table-driven subtest is missing t.Parallel()",
                );
            }
        }
    });
}

pub(crate) fn detect_bp_22_testmain_without_os_exit(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    walk_functions(unit, out, |function, src, unit, out| {
        if function_name(function, src) != Some("TestMain") {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        if !contains_call(body, src, "os.Exit") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_22_META,
                function.start_byte(),
                "TestMain should call os.Exit(m.Run()) so the process exits with the test result",
            );
        }
    });
}

pub(crate) fn detect_bp_23_missing_testing_short_guard(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    walk_functions(unit, out, |function, src, unit, out| {
        if !is_test_function(function, src) {
            return;
        }
        let Some(body) = function.child_by_field_name("body") else {
            return;
        };
        let (start_line, _) = unit.line_col(function.start_byte());
        let (end_line, _) = unit.line_col(function.end_byte());
        if end_line.saturating_sub(start_line) >= 20 && !contains_call(body, src, "testing.Short") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_23_META,
                function.start_byte(),
                "long-running test should gate itself with testing.Short()",
            );
        }
    });
}

pub(crate) fn detect_bp_24_test_file_without_tests(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut has_test = false;

    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if child.kind() == "function_declaration" && is_test_function(child, src) {
            has_test = true;
            break;
        }
    }

    if !has_test {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_24_META,
            root.start_byte(),
            "test file defines no Test* functions",
        );
    }
}

pub(crate) fn detect_bp_25_test_helper_returns_error(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if !is_test_file(unit) {
        return;
    }
    walk_functions(unit, out, |function, src, unit, out| {
        let Some(name) = function_name(function, src) else {
            return;
        };
        if !looks_like_test_helper(name, function, src) {
            return;
        }
        let Some(result) = function.child_by_field_name("result") else {
            return;
        };
        if result
            .utf8_text(src)
            .ok()
            .is_some_and(|text| text.contains("error"))
        {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_25_META,
                function.start_byte(),
                "test helper returns error instead of failing the test directly",
            );
        }
    });
}

fn walk_call_expressions(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    mut visit: impl FnMut(Node, &[u8], &ParsedUnit, &mut Vec<Finding>),
) {
    fn walk(
        node: Node,
        src: &[u8],
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        visit: &mut impl FnMut(Node, &[u8], &ParsedUnit, &mut Vec<Finding>),
    ) {
        if node.kind() == "call_expression" {
            visit(node, src, unit, out);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, unit, out, visit);
        }
    }

    walk(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        unit,
        out,
        &mut visit,
    );
}

fn walk_functions(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    mut visit: impl FnMut(Node, &[u8], &ParsedUnit, &mut Vec<Finding>),
) {
    fn walk(
        node: Node,
        src: &[u8],
        unit: &ParsedUnit,
        out: &mut Vec<Finding>,
        visit: &mut impl FnMut(Node, &[u8], &ParsedUnit, &mut Vec<Finding>),
    ) {
        if node.kind() == "function_declaration" {
            visit(node, src, unit, out);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, unit, out, visit);
        }
    }

    walk(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        unit,
        out,
        &mut visit,
    );
}

fn call_name<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(src).ok()
}

fn function_name<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("name")?.utf8_text(src).ok()
}

fn is_test_function(node: Node, src: &[u8]) -> bool {
    function_name(node, src).is_some_and(|name| name.starts_with("Test") && name != "TestMain")
}

fn looks_like_test_helper(name: &str, node: Node, src: &[u8]) -> bool {
    name.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_lowercase())
        && node
            .child_by_field_name("parameters")
            .and_then(|params| params.utf8_text(src).ok())
            .is_some_and(|text| text.contains("*testing.T"))
}

fn contains_call(node: Node, src: &[u8], wanted: &str) -> bool {
    let mut found = false;
    fn walk(node: Node, src: &[u8], wanted: &str, found: &mut bool) {
        if *found {
            return;
        }
        if node.kind() == "call_expression" && call_name(node, src) == Some(wanted) {
            *found = true;
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, wanted, found);
        }
    }
    walk(node, src, wanted, &mut found);
    found
}

fn contains_kind(node: Node, wanted: &str) -> bool {
    let mut found = false;
    fn walk(node: Node, wanted: &str, found: &mut bool) {
        if *found {
            return;
        }
        if node.kind() == wanted {
            *found = true;
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, wanted, found);
        }
    }
    walk(node, wanted, &mut found);
    found
}

fn has_loop_ancestor(node: Node) -> bool {
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(parent.kind(), "for_statement" | "range_statement") {
            return true;
        }
        current = parent.parent();
    }
    false
}

fn first_non_empty_body_line(body_text: &str) -> Option<&str> {
    body_text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && *line != "{")
}
