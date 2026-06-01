//! Language plugins registry.

#[cfg(feature = "go")]
pub mod go;

#[cfg(feature = "python")]
pub mod python;

use crate::core::LanguagePlugin;

/// Plugins enabled by Cargo features.
pub fn enabled_plugins() -> Vec<Box<dyn LanguagePlugin>> {
    #[cfg(all(feature = "go", feature = "python"))]
    let plugins = vec![
        Box::new(go::GoPlugin) as Box<dyn LanguagePlugin>,
        Box::new(python::PythonPlugin),
    ];

    #[cfg(all(feature = "go", not(feature = "python")))]
    let plugins = vec![Box::new(go::GoPlugin)];

    #[cfg(all(feature = "python", not(feature = "go")))]
    let plugins = vec![Box::new(python::PythonPlugin)];

    #[cfg(not(any(feature = "go", feature = "python")))]
    let plugins: Vec<Box<dyn LanguagePlugin>> = vec![];

    plugins
}
