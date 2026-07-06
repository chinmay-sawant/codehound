//! Compile-time language plugin registration via [`inventory`].

use crate::core::LanguagePlugin;

/// One registrar entry submitted by each enabled language feature.
pub struct LanguagePluginRegistrar(pub fn() -> Box<dyn LanguagePlugin>);

inventory::collect!(LanguagePluginRegistrar);

/// Collect every feature-gated plugin registrar into a runtime list.
pub fn enabled_plugins() -> Vec<Box<dyn LanguagePlugin>> {
    inventory::iter::<LanguagePluginRegistrar>
        .into_iter()
        .map(|registrar| (registrar.0)())
        .collect()
}
