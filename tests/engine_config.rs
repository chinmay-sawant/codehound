use std::path::Path;
use std::sync::{Mutex, OnceLock};

use slopguard::core::{FailPolicy, ScanContext};
use slopguard::engine::{
    Analyzer, SlopguardConfig, SlopguardSection, discover_config, fail_on_to_policy,
};
use slopguard::fixture::{materialize_tree, materialized_root};

fn runtime_filter_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn deny_unknown_fields_at_top_level() {
    let r = toml::from_str::<SlopguardConfig>(r#"unknown = 1"#);
    assert!(r.is_err(), "expected error for unknown field, got {r:?}");
}

#[test]
fn deny_unknown_fields_in_section() {
    let r = toml::from_str::<SlopguardConfig>(
        r#"[slopguard]
fali_on = "high"
"#,
    );
    assert!(r.is_err(), "expected typo to fail, got {r:?}");
}

#[test]
fn allow_known_fields() {
    let r = toml::from_str::<SlopguardConfig>(
        r#"[slopguard]
languages = ["go"]
skip = ["CWE-15"]
only = []
include = []
exclude = []
"#,
    );
    assert!(r.is_ok(), "expected ok, got {r:?}");
}

#[test]
fn fail_on_string_maps_to_policy() {
    assert!(matches!(fail_on_to_policy("none"), FailPolicy::NoFail));
    assert!(matches!(fail_on_to_policy("never"), FailPolicy::NoFail));
    assert!(matches!(fail_on_to_policy("high"), FailPolicy::Strict));
    assert!(matches!(fail_on_to_policy("strict"), FailPolicy::Strict));
    assert!(matches!(
        fail_on_to_policy("warnings"),
        FailPolicy::WarningsAsErrors
    ));
}

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
        fail_policy: FailPolicy::WarningsAsErrors,
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
fn runtime_include_exclude_filters_apply_during_collection() {
    let _guard = runtime_filter_test_lock()
        .lock()
        .expect("lock runtime filter test");
    materialize_tree(Path::new("tests/fixtures")).expect("materialize");

    let config = SlopguardConfig {
        slopguard: SlopguardSection {
            include: vec!["**/*.go".to_string()],
            exclude: vec!["**/frameworks/**".to_string()],
            ..Default::default()
        },
    };
    config.install_runtime_path_filters();

    let analyzer = Analyzer::builder().build();
    let result = analyzer
        .analyze_paths([materialized_root()])
        .expect("analyze with runtime filters");

    SlopguardConfig::clear_runtime_path_filters();

    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.file.ends_with(".go")),
        "include filter should keep only Go files: {:?}",
        result
            .findings
            .iter()
            .map(|finding| finding.file.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| !finding.file.contains("/frameworks/")),
        "exclude filter should remove framework fixtures: {:?}",
        result
            .findings
            .iter()
            .map(|finding| finding.file.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn schema_file_is_valid_json_and_covers_known_fields() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("slopguard.schema.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse schema: {e}"));
    let props = v
        .pointer("/properties/slopguard/properties")
        .expect("schema.properties.slopguard.properties");
    for field in ["languages", "fail_on", "skip", "only", "include", "exclude"] {
        assert!(
            props.get(field).is_some(),
            "schema must describe `{field}`; got keys: {:?}",
            props.as_object().map(|o| o.keys().collect::<Vec<_>>())
        );
    }
    assert_eq!(
        v.pointer("/properties/slopguard/additionalProperties"),
        Some(&serde_json::Value::Bool(false))
    );
}
