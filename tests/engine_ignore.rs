use slopguard::engine::{IgnoreDirective, parse_file_ignore, parse_inline_ignores};

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

#[test]
fn parse_file_ignore_without_rules_means_all_rules() {
    let ignore = parse_file_ignore("// slopguard-ignore-file\npackage sample\n");

    assert_eq!(ignore, Some(IgnoreDirective::all()));
}

#[test]
fn parse_file_ignore_all_rules() {
    let ignore = parse_file_ignore("// slopguard-ignore-file: all\npackage sample\n");

    assert_eq!(ignore, Some(IgnoreDirective::all()));
}

#[test]
fn parse_file_ignore_rule_list() {
    let ignore = parse_file_ignore("// slopguard-ignore-file: CWE-22, CWE-78\npackage sample\n");

    assert_eq!(
        ignore,
        Some(IgnoreDirective::rules(vec![
            "CWE-22".to_string(),
            "CWE-78".to_string()
        ]))
    );
}

#[test]
fn parse_file_ignore_ignores_directives_after_line_twenty() {
    let source = format!(
        "{}// slopguard-ignore-file: all\npackage sample\n",
        "\n".repeat(20)
    );

    assert_eq!(parse_file_ignore(&source), None);
}
