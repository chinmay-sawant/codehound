#![cfg(feature = "go")]

use codehound::lang::go::detectors::cwe::common::argument_uses_identifier;

#[test]
fn argument_uses_identifier_exact_match() {
    assert!(argument_uses_identifier("path", "path"));
}

#[test]
fn argument_uses_identifier_substring_in_call() {
    assert!(argument_uses_identifier(
        "filepath.Join(base, path)",
        "path"
    ));
}

#[test]
fn argument_uses_identifier_no_match() {
    assert!(!argument_uses_identifier("otherVar", "path"));
}

#[test]
fn argument_uses_identifier_underscore_not_split() {
    assert!(!argument_uses_identifier("user_name", "user"));
}

#[test]
fn argument_uses_identifier_empty_argument() {
    assert!(!argument_uses_identifier("", "path"));
}

#[test]
fn argument_uses_identifier_dot_separated() {
    assert!(argument_uses_identifier("v.Name", "v"));
    assert!(argument_uses_identifier("v.Name", "Name"));
}
