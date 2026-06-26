#![cfg(feature = "go")]

use slopguard::lang::go::detectors::cwe::facts::*;

#[test]
fn split_assignment_handles_both_forms() {
    assert_eq!(split_assignment("a := b"), Some(("a", "b")));
    assert_eq!(split_assignment("a = b"), Some(("a", "b")));
    assert_eq!(split_assignment("a"), None);
    assert_eq!(split_assignment("a, b := 1, 2"), Some(("a, b", "1, 2")));
}

#[test]
fn extract_identifiers_handles_empty_and_multi() {
    assert_eq!(extract_identifiers(""), Vec::<&str>::new());
    assert_eq!(extract_identifiers("a"), vec!["a"]);
    assert_eq!(extract_identifiers("a, b, c"), vec!["a", "b", "c"]);
    assert_eq!(extract_identifiers("  a  ,  b  "), vec!["a", "b"]);
}

#[test]
fn is_user_input_expr_matches_common_patterns() {
    assert!(is_user_input_expr(r#"r.URL.Query().Get("x")"#));
    assert!(is_user_input_expr(r#"c.PostForm("x")"#));
    assert!(is_user_input_expr("io.ReadAll(r.Body)"));
    assert!(!is_user_input_expr(r#"os.Getenv("X")"#));
    assert!(!is_user_input_expr("42"));
}
