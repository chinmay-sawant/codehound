use codehound::core::LanguageId;
use codehound::engine::{
    CodehoundConfig, CodehoundSection, LanguageFilter, Registry, resolve_language_filter,
};

#[test]
fn cli_lang_overrides_config_languages() {
    let registry = Registry::default();
    let config = CodehoundConfig {
        codehound: CodehoundSection {
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
    let config = CodehoundConfig {
        codehound: CodehoundSection {
            languages: vec!["rust".into()],
            ..Default::default()
        },
    };
    let err = resolve_language_filter(None, Some(&config), &registry).unwrap_err();
    assert!(err.to_string().contains("unknown language"), "{err:#}");
}
