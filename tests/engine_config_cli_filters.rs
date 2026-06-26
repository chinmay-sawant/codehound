use clap::Parser;
use slopguard::cli::{Cli, RuleCategory};
use slopguard::core::ScanContext;
use slopguard::engine::SlopguardConfig;

#[test]
fn scan_context_can_disable_bad_practice_category() {
    let ctx = ScanContext {
        bad_practices_enabled: false,
        ..Default::default()
    };

    assert!(!ctx.allows("BP-1"));
    assert!(ctx.allows("CWE-89"));
}

#[test]
fn cli_bp_only_sets_bp_prefix_filter() {
    let cli = Cli::try_parse_from(["slopguard", "--bp-only"]).unwrap();
    let ctx = cli.scan_context(None);

    assert!(ctx.allows("BP-1"));
    assert!(!ctx.allows("PERF-1"));
}

#[test]
fn cli_bp_only_overrides_config_disabled_bp() {
    let cli = Cli::try_parse_from(["slopguard", "--bp-only"]).unwrap();
    let cfg = toml::from_str::<SlopguardConfig>(
        r#"[slopguard]
[slopguard.bad_practices]
enabled = false
"#,
    )
    .unwrap();
    let ctx = cli.scan_context(Some(cfg));

    assert!(ctx.allows("BP-1"));
    assert!(!ctx.allows("CWE-89"));
}

#[test]
fn cli_no_bp_disables_bad_practice_category() {
    let cli = Cli::try_parse_from(["slopguard", "--no-bp"]).unwrap();
    let ctx = cli.scan_context(None);

    assert!(!ctx.allows("BP-1"));
    assert!(ctx.allows("PERF-1"));
}

#[test]
fn cli_list_rules_accepts_bad_practice_category_filter() {
    let cli = Cli::try_parse_from([
        "slopguard",
        "--list-rules",
        "--rule-category",
        "bad-practice",
    ])
    .unwrap();

    assert!(cli.list_rules);
    assert_eq!(cli.rule_category, Some(RuleCategory::BadPractice));
}
