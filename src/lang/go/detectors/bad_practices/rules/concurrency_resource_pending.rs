//! Pending concurrency/resource candidates with local, syntax-provable checks.
//!
//! These rules deliberately avoid race detection, ownership inference, and
//! interprocedural control-flow reasoning. The coordinator owns registration,
//! metadata, and documentation for these candidates.

use tree_sitter::Node;

use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// BP-90: an infinite loop performs a bare channel receive without a visible
/// escape. A select/break/return is treated as an explicit local escape; a
/// range loop is not inspected because it already has channel-close syntax.
pub(crate) fn detect_bp_90_channel_receive_loop_without_exit(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "for_statement" {
                    return;
                }
                let Ok(text) = node.utf8_text(source) else {
                    return;
                };
                if !text.trim_start().starts_with("for {")
                    || text.contains("select")
                    || text.contains("break")
                    || text.contains("return")
                    || !contains_receive(node, source)
                {
                    return;
                }
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_90_META,
                    node.start_byte(),
                    "infinite loop receives from a channel without a visible local exit",
                );
            });
        },
    );
}

/// BP-91: a boolean/integer channel is used only as a notification channel.
/// The detector requires a constant notification send and a receive whose
/// value is discarded (case receive or a standalone receive statement).
pub(crate) fn detect_bp_91_data_bearing_notification_channel(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            let Ok(text) = function.utf8_text(source) else {
                return;
            };
            let channels = notification_channel_names(text);
            if channels.is_empty() {
                return;
            }

            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "send_statement" {
                    return;
                }
                let Ok(send) = node.utf8_text(source) else {
                    return;
                };
                let Some((channel, value)) = send.split_once("<-") else {
                    return;
                };
                let channel = channel.trim();
                let value = value.trim();
                if !channels.iter().any(|candidate| candidate == channel)
                    || !matches!(value.trim_end_matches(';'), "true" | "1")
                {
                    return;
                }
                if !has_discarded_receive(body, source, channel) {
                    return;
                }
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_91_META,
                    node.start_byte(),
                    "notification channel carries a boolean/integer payload; use chan struct{}",
                );
            });
        },
    );
}

/// BP-92: a locally declared errgroup is used without the cancellation-aware
/// constructor. This is limited to explicit var g errgroup.Group bindings.
pub(crate) fn detect_bp_92_errgroup_without_context(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source_text = unit.source.as_ref();
    if !source_text.contains("golang.org/x/sync/errgroup") {
        return;
    }

    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Ok(text) = function.utf8_text(source) else {
                return;
            };
            if text.contains("errgroup.WithContext(") {
                return;
            }
            let Some((group, byte)) = errgroup_value_binding(function, source) else {
                return;
            };
            if !text.contains(&format!("{group}.Go(")) {
                return;
            }
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_92_META,
                byte,
                "errgroup.Group is used without errgroup.WithContext for cancellation propagation",
            );
        },
    );
}

/// BP-93: an errgroup Go closure explicitly discards a call result. Only blank
/// assignments are reported; an arbitrary expression statement is not enough
/// to prove that the callee returns an error.
pub(crate) fn detect_bp_93_errgroup_closure_discards_error(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let source_text = unit.source.as_ref();
    if !source_text.contains("golang.org/x/sync/errgroup") {
        return;
    }

    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "call_expression" || !is_method_call(node, source, "Go") {
                    return;
                }
                let Ok(text) = node.utf8_text(source) else {
                    return;
                };
                let Some((line, offset)) = unchecked_error_assignment(text) else {
                    return;
                };
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_93_META,
                    node.start_byte() + offset + line.find('_').unwrap_or(0),
                    "errgroup.Go closure discards a call result instead of returning or handling the error",
                );
            });
        },
    );
}

/// BP-94: a goroutine writes through a map index while the enclosing function
/// has no visible synchronization primitive. This reports only index
/// assignments, not reads or general shared-state access.
pub(crate) fn detect_bp_94_goroutine_map_write_without_sync(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Ok(function_text) = function.utf8_text(source) else {
                return;
            };
            if !has_map_declaration(function_text) || has_map_synchronization(function_text) {
                return;
            }
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "go_statement" {
                    return;
                }
                let Ok(text) = node.utf8_text(source) else {
                    return;
                };
                if !text.lines().any(looks_like_map_index_assignment) {
                    return;
                }
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_94_META,
                    node.start_byte(),
                    "goroutine writes to a map index without visible synchronization",
                );
            });
        },
    );
}

/// BP-96: a local Query/QueryContext result with a rows-like name is not
/// visibly closed or transferred. QueryRow is excluded because sql.Row has no
/// Close method.
pub(crate) fn detect_bp_96_sql_rows_without_close(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            let Ok(function_text) = function.utf8_text(source) else {
                return;
            };
            walk_scope(body, body, source, &mut |node| {
                if node.kind() != "call_expression" || !is_query_call(node, source) {
                    return;
                }
                let Some(name) = assignment_name_before(source, node.start_byte()) else {
                    return;
                };
                if !looks_like_rows_name(&name) {
                    return;
                }
                if function_text.contains(&format!("{name}.Close("))
                    || function_text.contains(&format!("return {name}"))
                {
                    return;
                }
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_96_META,
                    node.start_byte(),
                    "sql query rows are not visibly closed or transferred to the caller",
                );
            });
        },
    );
}

/// BP-97: a bufio/gzip writer writes into a buffer that is read before the
/// writer is flushed or closed. The underlying target and writer are both
/// required to be local names, keeping the proof obligation deliberately small.
pub(crate) fn detect_bp_97_writer_not_flushed_before_read(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            let Ok(text) = function.utf8_text(source) else {
                return;
            };
            let Some((writer, target, byte)) = writer_binding(body, source) else {
                return;
            };
            if !text.contains(&format!("{writer}.Write"))
                || text.contains(&format!("{writer}.Flush("))
                || text.contains(&format!("{writer}.Close("))
                || !has_buffer_read(text, &target)
            {
                return;
            }
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_97_META,
                byte,
                "buffer-backed writer is read before Flush or Close makes its data visible",
            );
        },
    );
}

/// BP-100: a range loop launches a goroutine per item without a visible bound.
/// A semaphore token pair, errgroup limit, or worker-pool marker suppresses the
/// finding; proving that those mechanisms are actually correct is out of scope.
pub(crate) fn detect_bp_100_unbounded_goroutine_fanout(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    inspect_functions(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        |function, source| {
            let Some(body) = function.child_by_field_name("body") else {
                return;
            };
            let Ok(function_text) = function.utf8_text(source) else {
                return;
            };
            if has_fanout_bound(function_text) {
                return;
            }
            walk_scope(body, body, source, &mut |node| {
                if !matches!(node.kind(), "range_statement" | "for_statement") {
                    return;
                }
                let Ok(text) = node.utf8_text(source) else {
                    return;
                };
                if !text.contains("range") || (!text.contains("go ") && !text.contains("go func")) {
                    return;
                }
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_100_META,
                    node.start_byte(),
                    "range loop launches one goroutine per item without a visible concurrency bound",
                );
            });
        },
    );
}

fn inspect_functions(root: Node, source: &[u8], inspect: impl FnMut(Node, &[u8])) {
    fn walk(node: Node, source: &[u8], inspect: &mut impl FnMut(Node, &[u8])) {
        if is_function(node) {
            inspect(node, source);
            return;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, source, inspect);
        }
    }
    let mut inspect = inspect;
    walk(root, source, &mut inspect);
}

fn walk_scope(node: Node, scope: Node, source: &[u8], visit: &mut impl FnMut(Node)) {
    if node.id() != scope.id() && is_function(node) {
        return;
    }
    visit(node);
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk_scope(child, scope, source, visit);
    }
    let _ = source;
}

fn is_function(node: Node) -> bool {
    matches!(
        node.kind(),
        "function_declaration" | "method_declaration" | "func_literal"
    )
}

fn contains_receive(node: Node, source: &[u8]) -> bool {
    if node.kind() == "receive_expression"
        || (node.kind() == "unary_expression"
            && node
                .utf8_text(source)
                .is_ok_and(|text| text.trim_start().starts_with("<-")))
    {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| contains_receive(child, source))
}

fn notification_channel_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (name, declaration) = trimmed.split_once("chan ")?;
            let name = name
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .filter_map(simple_identifier)
                .next_back()?;
            (declaration.starts_with("bool") || declaration.starts_with("int"))
                .then(|| name.to_owned())
        })
        .collect()
}

fn has_discarded_receive(body: Node, source: &[u8], channel: &str) -> bool {
    let body_text = body.utf8_text(source).unwrap_or_default();
    if body_text.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == format!("<-{channel}")
            || trimmed == format!("<- {channel}")
            || trimmed == format!("case <-{channel}:")
            || trimmed == format!("case <- {channel}:")
    }) {
        return true;
    }

    let mut found = false;
    walk_scope(body, body, source, &mut |node| {
        if found || node.kind() != "receive_expression" {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        if text.trim() != format!("<-{channel}") && text.trim() != format!("<- {channel}") {
            return;
        }
        let Some(parent) = node.parent() else {
            return;
        };
        found = parent.kind() == "expression_case" || parent.kind() == "expression_statement";
    });
    found
}

fn errgroup_value_binding(function: Node, source: &[u8]) -> Option<(String, usize)> {
    let mut result = None;
    walk_scope(function, function, source, &mut |node| {
        if result.is_some() || node.kind() != "var_declaration" {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        let trimmed = text.trim();
        let Some(rest) = trimmed.strip_prefix("var ") else {
            return;
        };
        let mut parts = rest.split_whitespace();
        let Some(name) = parts.next() else {
            return;
        };
        if parts.next() == Some("errgroup.Group") {
            result = Some((name.to_owned(), node.start_byte()));
        }
    });
    result
}

fn is_method_call(node: Node, source: &[u8], method: &str) -> bool {
    node.child_by_field_name("function")
        .and_then(|function| function.utf8_text(source).ok())
        .is_some_and(|callee| callee.ends_with(&format!(".{method}")))
}

fn unchecked_error_assignment(text: &str) -> Option<(&str, usize)> {
    text.lines().enumerate().find_map(|(line_no, line)| {
        let trimmed = line.trim();
        let assignment = trimmed
            .strip_prefix("_ = ")
            .or_else(|| trimmed.strip_prefix("_, _ = "))?;
        if !assignment.contains('(') {
            return None;
        }
        let offset = text
            .lines()
            .take(line_no)
            .map(|previous| previous.len() + 1)
            .sum::<usize>();
        Some((line, offset + line.len() - trimmed.len()))
    })
}

fn has_map_declaration(text: &str) -> bool {
    text.contains("map[") || text.contains("make(map")
}

fn has_map_synchronization(text: &str) -> bool {
    text.contains("sync.Map")
        || text.contains(".Store(")
        || (text.contains(".Lock(") && text.contains(".Unlock("))
}

fn looks_like_map_index_assignment(line: &str) -> bool {
    let trimmed = line.trim();
    (trimmed.contains("] =") || trimmed.contains("]=")) && !trimmed.starts_with("//")
}

fn is_query_call(node: Node, source: &[u8]) -> bool {
    let Some(callee) = node
        .child_by_field_name("function")
        .and_then(|function| function.utf8_text(source).ok())
    else {
        return false;
    };
    (callee.ends_with(".Query") || callee.ends_with(".QueryContext"))
        && !callee.ends_with("QueryRow")
}

fn assignment_name_before(source: &[u8], byte: usize) -> Option<String> {
    let source = std::str::from_utf8(source).ok()?;
    let line_start = source[..byte].rfind('\n').map_or(0, |index| index + 1);
    let line = source[line_start..].lines().next()?.trim();
    let lhs = line
        .split_once(":=")
        .map(|(left, _)| left)
        .or_else(|| line.split_once('=').map(|(left, _)| left))?;
    let name = lhs
        .trim()
        .strip_prefix("var ")
        .unwrap_or(lhs.trim())
        .split(',')
        .next()?
        .trim();
    simple_identifier(name).map(str::to_owned)
}

fn looks_like_rows_name(name: &str) -> bool {
    matches!(name, "rows" | "rs" | "result" | "records")
}

fn writer_binding(body: Node, source: &[u8]) -> Option<(String, String, usize)> {
    let mut result = None;
    walk_scope(body, body, source, &mut |node| {
        if result.is_some() || !matches!(node.kind(), "short_var_declaration" | "var_declaration") {
            return;
        }
        let Ok(text) = node.utf8_text(source) else {
            return;
        };
        let Some((lhs, rhs)) = text.split_once(":=").or_else(|| text.split_once('=')) else {
            return;
        };
        let Some(writer) = simple_identifier(lhs.trim().strip_prefix("var ").unwrap_or(lhs.trim()))
        else {
            return;
        };
        let constructors = [
            "bufio.NewWriter(",
            "bufio.NewWriterSize(",
            "gzip.NewWriter(",
            "gzip.NewWriterLevel(",
        ];
        let Some(constructor) = constructors
            .iter()
            .find(|constructor| rhs.contains(*constructor))
        else {
            return;
        };
        let Some(start) = rhs
            .find(*constructor)
            .map(|index| index + constructor.len())
        else {
            return;
        };
        let Some(target) = rhs[start..].split([',', ')']).next().map(str::trim) else {
            return;
        };
        let Some(target) = simple_identifier(target) else {
            return;
        };
        result = Some((writer.to_owned(), target.to_owned(), node.start_byte()));
    });
    result
}

fn has_buffer_read(text: &str, target: &str) -> bool {
    [".String(", ".Bytes(", ".Len(", ".Read("]
        .iter()
        .any(|method| text.contains(&format!("{target}{method}")))
}

fn has_fanout_bound(text: &str) -> bool {
    // A WaitGroup still permits unbounded fan-out, but BP-6 owns that
    // coordination shape; keep this rule focused on otherwise unmanaged
    // goroutine creation and avoid duplicate findings.
    text.contains("WaitGroup")
        || (text.contains("errgroup.WithContext(")
            && (text.contains(".SetLimit(") || text.contains(".TryGo(")))
        || text.contains("semaphore.NewWeighted(")
        || ((text.contains(" <- struct{}{}") || text.contains("<- struct{}{}"))
            && (text.contains("<-sem") || text.contains("<- tokens")))
        || (text.contains("jobs <-") && text.contains("worker"))
}

fn simple_identifier(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_'))
    .then_some(value)
}
