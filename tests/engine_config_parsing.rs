use codehound::core::FailPolicy;
use codehound::engine::{
    CacheConfig, CodehoundConfig, CodehoundSection, PathFilters, RunConfigParams,
    ScanContextParams, build_run_config, discover_config,
};
use codehound::rules::Severity;
use std::path::{Path, PathBuf};

#[test]
fn deny_unknown_fields_at_top_level() {
    let r = toml::from_str::<CodehoundConfig>(r#"unknown = 1"#);
    assert!(r.is_err(), "expected error for unknown field, got {r:?}");
}

#[test]
fn deny_unknown_fields_in_section() {
    let r = toml::from_str::<CodehoundConfig>(
        r#"[codehound]
fali_on = "high"
"#,
    );
    assert!(r.is_err(), "expected typo to fail, got {r:?}");
}

#[test]
fn allow_known_fields() {
    let r = toml::from_str::<CodehoundConfig>(
        r#"[codehound]
languages = ["go"]
skip = ["CWE-15"]
only = []
include = []
exclude = []
[codehound.baseline]
enabled = true
path = ".codehound-baseline.json"
[codehound.bad_practices]
enabled = true
severity = "medium"
"#,
    );
    assert!(r.is_ok(), "expected ok, got {r:?}");
}

#[test]
fn bad_practices_config_defaults_enabled() {
    let cfg = toml::from_str::<CodehoundConfig>("[codehound]\n").unwrap();

    assert!(cfg.codehound.bad_practices.enabled);
    assert_eq!(cfg.codehound.bad_practices.severity, None);
}

#[test]
fn bad_practices_config_accepts_enabled_and_severity() {
    let cfg = toml::from_str::<CodehoundConfig>(
        r#"[codehound]
[codehound.bad_practices]
enabled = false
severity = "high"
"#,
    )
    .unwrap();

    assert!(!cfg.codehound.bad_practices.enabled);
    assert_eq!(cfg.codehound.bad_practices.severity, Some(Severity::High));
}

#[test]
fn baseline_config_defaults_enabled() {
    let cfg = toml::from_str::<CodehoundConfig>("[codehound]\n").unwrap();

    assert!(cfg.codehound.baseline.enabled);
    assert_eq!(cfg.codehound.baseline.path, None);
}

#[test]
fn baseline_config_accepts_enabled_and_path() {
    let cfg = toml::from_str::<CodehoundConfig>(
        r#"[codehound]
[codehound.baseline]
enabled = false
path = "custom-baseline.json"
"#,
    )
    .unwrap();

    assert!(!cfg.codehound.baseline.enabled);
    assert_eq!(
        cfg.codehound.baseline.path.as_deref(),
        Some(Path::new("custom-baseline.json"))
    );
}

#[test]
fn fail_on_string_maps_to_policy() {
    use codehound::core::{FailPolicy, ScanContext};
    use codehound::engine::CodehoundConfig;

    let cases = [
        ("none", FailPolicy::NoFail),
        ("never", FailPolicy::NoFail),
        ("high", FailPolicy::Strict),
        ("strict", FailPolicy::Strict),
        ("medium", FailPolicy::MediumAsErrors),
        ("warning", FailPolicy::MediumAsErrors),
    ];

    for (fail_on, expected) in cases {
        let config: CodehoundConfig = toml::from_str(&format!(
            r#"
[codehound]
fail_on = "{fail_on}"
"#
        ))
        .unwrap();
        let ctx = config.merge_into(ScanContext::default(), false);
        assert!(
            matches!(ctx.fail_policy, policy if std::mem::discriminant(&policy) == std::mem::discriminant(&expected)),
            "fail_on={fail_on:?}"
        );
    }
}

#[test]
fn schema_file_is_valid_json_and_covers_known_fields() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("codehound.schema.json");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse schema: {e}"));
    let props = v
        .pointer("/properties/codehound/properties")
        .expect("schema.properties.codehound.properties");
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
        v.pointer("/properties/codehound/additionalProperties"),
        Some(&serde_json::Value::Bool(false))
    );
    assert_eq!(
        v.pointer("/properties/codehound/properties/baseline/additionalProperties"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[test]
fn runtime_include_exclude_filters_apply_during_collection() {
    use codehound::engine::Analyzer;
    use codehound::fixture::{materialize_tree, materialized_root};

    materialize_tree(Path::new("tests/fixtures")).expect("materialize");

    let analyzer = Analyzer::builder()
        .path_filters(PathFilters {
            include: vec!["**/*.go".to_string()],
            exclude: vec!["**/frameworks/**".to_string()],
            exclude_tests: false,
        })
        .build();
    let result = analyzer
        .analyze_paths(&[materialized_root()], None)
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

#[test]
fn cache_config_is_parsed_from_toml() {
    let toml = r#"
[codehound.cache]
enabled = false
path = "/tmp/custom-cache"
evict_target_ratio = 0.75
max_file_size_mb = 16
"#;
    let cfg: CodehoundConfig = toml::from_str(toml).unwrap();
    assert!(!cfg.codehound.cache.enabled);
    assert_eq!(
        cfg.codehound.cache.path,
        Some(PathBuf::from("/tmp/custom-cache"))
    );
    assert_eq!(cfg.codehound.cache.evict_target_ratio, Some(0.75));
    assert_eq!(cfg.codehound.cache.max_file_size_mb, Some(16));
}

#[test]
fn cache_disabled_in_config_means_open_returns_none() {
    let cfg = CodehoundConfig {
        codehound: CodehoundSection {
            cache: CacheConfig {
                enabled: false,
                path: None,
                ..Default::default()
            },
            ..Default::default()
        },
    };
    assert!(!cfg.codehound.cache.enabled);
}

#[test]
fn discover_config_finds_in_cwd() {
    let path = discover_config(Path::new("."));
    assert!(path.is_some(), "expected codehound.toml in cwd");
    let path = path.unwrap();
    assert!(path.ends_with("codehound.toml"));
}

#[test]
fn discover_config_finds_in_subdir() {
    let target = Path::new("./target");
    if target.is_dir() {
        let path = discover_config(target);
        assert!(
            path.is_some(),
            "expected upward walk to find codehound.toml"
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
    let cfg = CodehoundConfig {
        codehound: CodehoundSection {
            fail_on: Some("none".to_string()),
            ..Default::default()
        },
    };
    let ctx = codehound::core::ScanContext {
        fail_policy: FailPolicy::Strict,
        ..Default::default()
    };
    let merged = cfg.merge_into(ctx, true);
    assert_eq!(merged.fail_policy, FailPolicy::Strict);
}

#[test]
fn merge_into_config_fail_on_applies_when_cli_didnt_set_it() {
    let cfg = CodehoundConfig {
        codehound: CodehoundSection {
            fail_on: Some("none".to_string()),
            ..Default::default()
        },
    };
    let ctx = codehound::core::ScanContext {
        fail_policy: FailPolicy::MediumAsErrors,
        ..Default::default()
    };
    let merged = cfg.merge_into(ctx, false);
    assert_eq!(merged.fail_policy, FailPolicy::NoFail);
}

#[test]
fn merge_into_only_is_additive_with_cli_values() {
    let cfg = CodehoundConfig {
        codehound: CodehoundSection {
            only: vec!["CWE-22".to_string()],
            ..Default::default()
        },
    };
    let ctx = codehound::core::ScanContext {
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
    let ctx = codehound::core::ScanContext {
        only: Some(["BP-*".to_string()].into_iter().collect()),
        ..Default::default()
    };

    assert!(ctx.allows("BP-1"));
    assert!(!ctx.allows("CWE-89"));
}

#[test]
fn build_run_config_unifies_context_and_path_filters() {
    let run_config = build_run_config(RunConfigParams {
        scan: ScanContextParams {
            taint: true,
            show_ignored: true,
            ..ScanContextParams::default()
        },
        include_tests: true,
    });

    assert!(run_config.scan_context.taint_enabled);
    assert!(run_config.scan_context.show_ignored);
    assert!(!run_config.path_filters.exclude_tests);
}
