//! Line/column from byte offset.

use tree_sitter::Tree;

/// 1-indexed `(line, column)` for a byte offset in `tree`.
pub fn line_col(tree: &Tree, byte_offset: usize) -> (usize, usize) {
    tree.root_node()
        .descendant_for_byte_range(byte_offset, byte_offset)
        .map_or((1, 1), |n| {
            (n.start_position().row + 1, n.start_position().column + 1)
        })
}
