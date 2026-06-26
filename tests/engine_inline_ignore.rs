use slopguard::engine::{IgnoreDirective, parse_inline_ignores};

#[test]
fn parse_inline_ignore_single_rule_targets_next_code_line() {
    let ignores = parse_inline_ignores(
        r#"
// slopguard-ignore: CWE-22

value := input
"#,
    );

    assert_eq!(
        ignores.get(&4),
        Some(&IgnoreDirective::rules(vec!["CWE-22".to_string()]))
    );
}

#[test]
fn parse_inline_ignore_multi_rule() {
    let ignores = parse_inline_ignores("//slopguard-ignore:CWE-22, CWE-89\nrun()\n");

    assert_eq!(
        ignores.get(&2),
        Some(&IgnoreDirective::rules(vec![
            "CWE-22".to_string(),
            "CWE-89".to_string()
        ]))
    );
}

#[test]
fn parse_inline_ignore_all_rules() {
    let ignores = parse_inline_ignores("//  slopguard-ignore:  all  \nrun()\n");

    assert_eq!(ignores.get(&2), Some(&IgnoreDirective::all()));
}

#[test]
fn parse_inline_ignore_skips_comment_only_lines() {
    let ignores = parse_inline_ignores(
        r#"
// slopguard-ignore: CWE-22
// explanatory comment
run()
"#,
    );

    assert_eq!(
        ignores.get(&4),
        Some(&IgnoreDirective::rules(vec!["CWE-22".to_string()]))
    );
}

#[test]
fn parse_inline_ignore_ignores_non_matching_comments() {
    let ignores = parse_inline_ignores("// some other comment\nrun()\n");

    assert!(ignores.is_empty());
}
