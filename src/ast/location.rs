//! Line/column from byte offset.

use tree_sitter::Tree;

/// 1-indexed `(line, column)` for a byte offset in `tree`. O(tree depth).
pub fn line_col(tree: &Tree, byte_offset: usize) -> (usize, usize) {
    tree.root_node()
        .descendant_for_byte_range(byte_offset, byte_offset)
        .map_or((1, 1), |n| {
            (n.start_position().row + 1, n.start_position().column + 1)
        })
}

/// 1-indexed `(line, column)` for a byte offset using a precomputed per-line
/// start-offset table. O(log N) — used on the detector hot path where
/// `line_col` is called up to ~175 times per file.
pub fn line_col_with_starts(line_starts: &[usize], byte_offset: usize) -> (usize, usize) {
    if line_starts.is_empty() {
        return (1, 1);
    }
    let idx = match line_starts.binary_search(&byte_offset) {
        Ok(i) => i,
        Err(0) => return (1, 1),
        Err(i) => i - 1,
    };
    let line = idx + 1;
    let col = byte_offset - line_starts[idx] + 1;
    (line, col)
}

/// Build a per-line start-offset table from source text. The returned
/// `Vec<usize>` contains, in order, the byte offset of the first byte of each
/// line (always starting with `0`). Used to make `line_col` O(log N).
pub fn compute_line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, b) in source.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

