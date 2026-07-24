//! HTTP response-writer sink classification helpers.

use super::classify::receiver_of_method_call;

/// Heuristic: only treat a write as an HTTP XSS sink when its receiver is
/// declared as an `http.ResponseWriter` in the enclosing function.
pub(super) fn http_write_looks_like_response_writer(call: tree_sitter::Node, src: &[u8]) -> bool {
    if let Some(args) = call.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        if let Some(first) = args.named_children(&mut cursor).next()
            && let Ok(text) = first.utf8_text(src)
            && text.trim().starts_with("[]string")
        {
            // csv.Writer.Write([]string{...}) — not XSS.
            return false;
        }
    }
    receiver_of_method_call(call, src)
        .is_some_and(|receiver| declared_response_writer(call, receiver, src))
}

pub(super) fn http_argument_looks_like_response_writer(
    call: tree_sitter::Node,
    src: &[u8],
    argument_index: usize,
) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let Some(argument) = args.named_children(&mut cursor).nth(argument_index) else {
        return false;
    };
    argument
        .utf8_text(src)
        .ok()
        .is_some_and(|argument| declared_response_writer(call, argument.trim(), src))
}

fn declared_response_writer(call: tree_sitter::Node, name: &str, src: &[u8]) -> bool {
    // ponytail: parameter-text matching is limited to the enclosing function,
    // so same-named writers in sibling functions cannot collide. Upgrade to
    // typed facts if aliases or values passed through helper functions matter.
    enclosing_function(call)
        .and_then(|function| function.child_by_field_name("parameters"))
        .and_then(|parameters| parameters.utf8_text(src).ok())
        .is_some_and(|parameters| {
            parameters.contains(&format!("{name} http.ResponseWriter"))
                || parameters.contains(&format!("{name} *http.ResponseWriter"))
        })
}

fn enclosing_function(mut node: tree_sitter::Node) -> Option<tree_sitter::Node> {
    loop {
        node = node.parent()?;
        if matches!(
            node.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        ) {
            return Some(node);
        }
    }
}
