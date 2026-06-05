use slopguard::core::LanguageId;
use slopguard::engine::{
    LanguageFilter, Registry, SlopguardConfig, SlopguardSection, resolve_language_filter,
};

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

#[test]
fn unknown_config_language_errors() {
    let registry = Registry::default();
    let config = SlopguardConfig {
        slopguard: SlopguardSection {
            languages: vec!["rust".into()],
            ..Default::default()
        },
    };
    let err = resolve_language_filter(None, Some(&config), &registry).unwrap_err();
    assert!(err.to_string().contains("unknown language"), "{err:#}");
}
