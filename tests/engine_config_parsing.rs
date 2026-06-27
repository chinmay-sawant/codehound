use slopguard::engine::{PathFilters, SlopguardConfig};
use slopguard::rules::Severity;
use std::path::Path;

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
[slopguard.baseline]
enabled = true
path = ".slopguard-baseline.json"
[slopguard.bad_practices]
enabled = true
severity = "medium"
"#,
    );
    assert!(r.is_ok(), "expected ok, got {r:?}");
}

#[test]
fn bad_practices_config_defaults_enabled() {
    let cfg = toml::from_str::<SlopguardConfig>("[slopguard]\n").unwrap();

    assert!(cfg.bad_practices_enabled());
    assert_eq!(cfg.bad_practice_severity(), None);
}

#[test]
fn bad_practices_config_accepts_enabled_and_severity() {
    let cfg = toml::from_str::<SlopguardConfig>(
        r#"[slopguard]
[slopguard.bad_practices]
enabled = false
severity = "high"
"#,
    )
    .unwrap();

    assert!(!cfg.bad_practices_enabled());
    assert_eq!(cfg.bad_practice_severity(), Some(Severity::High));
}

#[test]
fn baseline_config_defaults_enabled() {
    let cfg = toml::from_str::<SlopguardConfig>("[slopguard]\n").unwrap();

    assert!(cfg.baseline_enabled());
    assert_eq!(cfg.baseline_path(), None);
}

#[test]
fn baseline_config_accepts_enabled_and_path() {
    let cfg = toml::from_str::<SlopguardConfig>(
        r#"[slopguard]
[slopguard.baseline]
enabled = false
path = "custom-baseline.json"
"#,
    )
    .unwrap();

    assert!(!cfg.baseline_enabled());
    assert_eq!(
        cfg.baseline_path().as_deref(),
        Some(Path::new("custom-baseline.json"))
    );
}

#[test]
fn fail_on_string_maps_to_policy() {
    use slopguard::core::FailPolicy;
    use slopguard::engine::fail_on_to_policy;

    assert!(matches!(fail_on_to_policy("none"), FailPolicy::NoFail));
    assert!(matches!(fail_on_to_policy("never"), FailPolicy::NoFail));
    assert!(matches!(fail_on_to_policy("high"), FailPolicy::Strict));
    assert!(matches!(fail_on_to_policy("strict"), FailPolicy::Strict));
    assert!(matches!(
        fail_on_to_policy("medium"),
        FailPolicy::MediumAsErrors
    ));
    assert!(matches!(
        fail_on_to_policy("warning"),
        FailPolicy::MediumAsErrors
    ));
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
    for field in [
        "languages",
        "fail_on",
        "skip",
        "only",
        "include",
        "exclude",
        "baseline",
        "cache",
        "taint",
        "bad_practices",
    ] {
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
    assert_eq!(
        v.pointer("/properties/slopguard/properties/baseline/additionalProperties"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[test]
fn runtime_include_exclude_filters_apply_during_collection() {
    use slopguard::engine::Analyzer;
    use slopguard::fixture::{materialize_tree, materialized_root};

    materialize_tree(Path::new("tests/fixtures")).expect("materialize");

    let analyzer = Analyzer::builder()
        .with_default_filter()
        .path_filters(PathFilters {
            include: vec!["**/*.go".to_string()],
            exclude: vec!["**/frameworks/**".to_string()],
            exclude_tests: false,
        })
        .build();
    let result = analyzer
        .analyze_paths([materialized_root()], None)
        .expect("analyze with runtime filters");

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
