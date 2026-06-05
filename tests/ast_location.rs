use slopguard::ast::{compute_line_starts, line_col_with_starts};

#[test]
fn compute_line_starts_single_line() {
    let starts = compute_line_starts("hello world");
    assert_eq!(starts, vec![0]);
}

#[test]
fn compute_line_starts_multiple_lines() {
    let starts = compute_line_starts("a\nb\nc");
    assert_eq!(starts, vec![0, 2, 4]);
}

#[test]
fn compute_line_starts_leading_newline() {
    let starts = compute_line_starts("\nabc");
    assert_eq!(starts, vec![0, 1]);
}

#[test]
fn compute_line_starts_trailing_newline() {
    let starts = compute_line_starts("abc\n");
    assert_eq!(starts, vec![0, 4]);
}

#[test]
fn compute_line_starts_empty_string() {
    let starts = compute_line_starts("");
    assert_eq!(starts, vec![0]);
}

#[test]
fn line_col_with_starts_first_line() {
    let starts = vec![0, 10, 20];
    assert_eq!(line_col_with_starts(&starts, 3), (1, 4));
}

#[test]
fn line_col_with_starts_second_line() {
    let starts = vec![0, 10, 20];
    assert_eq!(line_col_with_starts(&starts, 10), (2, 1));
    assert_eq!(line_col_with_starts(&starts, 15), (2, 6));
}

#[test]
fn line_col_with_starts_third_line() {
    let starts = vec![0, 10, 20];
    assert_eq!(line_col_with_starts(&starts, 25), (3, 6));
}

#[test]
fn line_col_with_starts_offset_before_first_line() {
    let starts = vec![5, 10, 20];
    assert_eq!(line_col_with_starts(&starts, 2), (1, 1));
}

#[test]
fn line_col_with_starts_offset_past_end() {
    let starts = vec![0, 10, 20];
    assert_eq!(line_col_with_starts(&starts, 100), (3, 81));
}

#[test]
fn line_col_with_starts_empty_starts() {
    let starts: Vec<usize> = vec![];
    assert_eq!(line_col_with_starts(&starts, 0), (1, 1));
    assert_eq!(line_col_with_starts(&starts, 5), (1, 1));
}

#[test]
fn line_col_with_starts_exact_boundary() {
    let starts = vec![0, 5, 10];
    assert_eq!(line_col_with_starts(&starts, 5), (2, 1));
    assert_eq!(line_col_with_starts(&starts, 10), (3, 1));
}
