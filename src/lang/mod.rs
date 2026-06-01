//! Language plugins registry.

#[cfg(feature = "go")]
pub mod go;

#[cfg(feature = "python")]
pub mod python;

use crate::core::LanguagePlugin;

/// Plugins enabled by Cargo features.
pub fn enabled_plugins() -> Vec<Box<dyn LanguagePlugin>> {
    let mut plugins: Vec<Box<dyn LanguagePlugin>> = Vec::new();
    #[cfg(feature = "go")]
    plugins.push(Box::new(go::GoPlugin));
    #[cfg(feature = "python")]
    plugins.push(Box::new(python::PythonPlugin));
    plugins
}
