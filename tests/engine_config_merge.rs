use slopguard::core::{FailPolicy, ScanContext};
use slopguard::engine::{SlopguardConfig, SlopguardSection, discover_config};
use std::path::Path;

#[test]
fn discover_config_finds_in_cwd() {
    let path = discover_config(Path::new("."));
    assert!(path.is_some(), "expected slopguard.toml in cwd");
    let path = path.unwrap();
    assert!(path.ends_with("slopguard.toml"));
}

#[test]
fn discover_config_finds_in_subdir() {
    let target = Path::new("./target");
    if target.is_dir() {
        let path = discover_config(target);
        assert!(
            path.is_some(),
            "expected upward walk to find slopguard.toml"
        );
    }
}

#[test]
fn discover_config_returns_none_outside_repo() {
    let path = discover_config(Path::new("/tmp"));
    assert!(path.is_none(), "expected None for /tmp, got {path:?}");
}

#[test]
fn merge_into_cli_fail_policy_wins_over_config() {
    let cfg = SlopguardConfig {
        slopguard: SlopguardSection {
            fail_on: Some("none".to_string()),
            ..Default::default()
        },
    };
    let ctx = ScanContext {
        fail_policy: FailPolicy::Strict,
        ..Default::default()
    };
    let merged = cfg.merge_into(ctx, true);
    assert_eq!(merged.fail_policy, FailPolicy::Strict);
}

#[test]
fn merge_into_config_fail_on_applies_when_cli_didnt_set_it() {
    let cfg = SlopguardConfig {
        slopguard: SlopguardSection {
            fail_on: Some("none".to_string()),
            ..Default::default()
        },
    };
    let ctx = ScanContext {
        fail_policy: FailPolicy::MediumAsErrors,
        ..Default::default()
    };
    let merged = cfg.merge_into(ctx, false);
    assert_eq!(merged.fail_policy, FailPolicy::NoFail);
}

#[test]
fn merge_into_only_is_additive_with_cli_values() {
    let cfg = SlopguardConfig {
        slopguard: SlopguardSection {
            only: vec!["CWE-22".to_string()],
            ..Default::default()
        },
    };
    let ctx = ScanContext {
        only: Some(["CWE-89".to_string()].into_iter().collect()),
        ..Default::default()
    };

    let merged = cfg.merge_into(ctx, false);
    let only = merged.only.expect("merged only set");
    assert!(only.contains("CWE-22"));
    assert!(only.contains("CWE-89"));
    assert_eq!(only.len(), 2);
}

#[test]
fn scan_context_supports_rule_prefix_filters() {
    let ctx = ScanContext {
        only: Some(["BP-*".to_string()].into_iter().collect()),
        ..Default::default()
    };

    assert!(ctx.allows("BP-1"));
    assert!(!ctx.allows("CWE-89"));
}
