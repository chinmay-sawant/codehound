//! Loop-context detection.

use tree_sitter::Node;

/// Returns the nearest ancestor whose kind is in `loop_kinds`.
pub fn nearest_loop<'a>(mut node: Node<'a>, loop_kinds: &[&str]) -> Option<Node<'a>> {
    while let Some(parent) = node.parent() {
        if loop_kinds.contains(&parent.kind()) {
            return Some(parent);
        }
        node = parent;
    }
    None
}
