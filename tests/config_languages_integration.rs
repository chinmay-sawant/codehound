//! `slopguard.toml` `languages` filtering and validation.

use std::collections::HashSet;
use std::path::Path;

use slopguard::core::{LanguageId, ScanContext};
use slopguard::engine::{
    Analyzer, LanguageFilter, Registry, SlopguardConfig, SlopguardSection, resolve_language_filter,
};
use slopguard::fixture::{materialize_tree, materialized_root};

#[test]
fn go_only_filter_skips_python_files() {
    materialize_tree(Path::new("tests/fixtures")).expect("materialize");

    let filter = LanguageFilter::Many(HashSet::from([LanguageId::Go]));
    let analyzer = Analyzer::builder()
        
        .scan_context(ScanContext::default())
        .language_filter(filter)
        .build();

    let result = analyzer
        .analyze_paths(&[materialized_root()], None)
        .expect("analyze");

    let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
    assert!(
        ids.iter().any(|id| id.starts_with("CWE-")),
        "expected at least one Go CWE finding with the go-only filter, got {ids:?}"
    );
    assert!(
        !ids.contains(&"SLOP101"),
        "python rule SLOP101 must be filtered out under a go-only filter, got {ids:?}"
    );
}

#[test]
fn unknown_config_language_fails_fast() {
    let registry = Registry::default();
    let config = SlopguardConfig {
        slopguard: SlopguardSection {
            languages: vec!["rust".into()],
            ..Default::default()
        },
    };
    let err = resolve_language_filter(None, Some(&config), &registry).unwrap_err();
    assert!(err.to_string().contains("unknown language"));
}

#[test]
fn cli_lang_overrides_config_languages() {
    let registry = Registry::default();
    let config = SlopguardConfig {
        slopguard: SlopguardSection {
            languages: vec!["python".into()],
            ..Default::default()
        },
    };
    let filter = resolve_language_filter(Some(LanguageId::Go), Some(&config), &registry).unwrap();
    assert_eq!(filter, LanguageFilter::One(LanguageId::Go));
}
