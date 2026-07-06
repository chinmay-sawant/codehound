use codehound::engine::{IgnoreDirective, parse_file_ignore};

#[test]
fn parse_file_ignore_without_rules_means_all_rules() {
    let ignore = parse_file_ignore("// codehound-ignore-file\npackage sample\n");

    assert_eq!(ignore, Some(IgnoreDirective::all()));
}

#[test]
fn parse_file_ignore_all_rules() {
    let ignore = parse_file_ignore("// codehound-ignore-file: all\npackage sample\n");

    assert_eq!(ignore, Some(IgnoreDirective::all()));
}

#[test]
fn parse_file_ignore_rule_list() {
    let ignore = parse_file_ignore("// codehound-ignore-file: CWE-22, CWE-78\npackage sample\n");

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
        "{}// codehound-ignore-file: all\npackage sample\n",
        "\n".repeat(20)
    );

    assert_eq!(parse_file_ignore(&source), None);
}
