//! Compile-time plugin registration via `inventory`.

use codehound::core::LanguageId;
use codehound::lang::enabled_plugins;

#[test]
fn enabled_plugins_collects_feature_gated_registrars() {
    let plugins = enabled_plugins();
    assert!(!plugins.is_empty());
    let ids: Vec<LanguageId> = plugins.iter().map(|p| p.id()).collect();
    #[cfg(feature = "go")]
    assert!(ids.contains(&LanguageId::Go));
    #[cfg(feature = "python")]
    assert!(ids.contains(&LanguageId::Python));
}
