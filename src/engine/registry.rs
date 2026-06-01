//! Detector and language plugin registry.

use std::collections::HashMap;
use std::path::Path;

use crate::core::{Detector, LanguageId, LanguagePlugin};

/// Holds enabled language plugins and detectors indexed by language.
pub struct Registry {
    plugins: Vec<Box<dyn LanguagePlugin>>,
    detectors: Vec<Box<dyn Detector>>,
    /// Detector indices grouped by language (avoids scanning all rules per file).
    by_language: HashMap<LanguageId, Vec<usize>>,
}

impl Registry {
    pub fn from_plugins(plugins: Vec<Box<dyn LanguagePlugin>>) -> Self {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
        let mut by_language: HashMap<LanguageId, Vec<usize>> = HashMap::new();

        for plugin in &plugins {
            for det in plugin.detectors() {
                let idx = detectors.len();
                by_language.entry(det.language()).or_default().push(idx);
                detectors.push(det);
            }
        }

        Self {
            plugins,
            detectors,
            by_language,
        }
    }

    pub fn detector_indices(&self, language: LanguageId) -> &[usize] {
        self.by_language
            .get(&language)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn detector(&self, index: usize) -> &dyn Detector {
        self.detectors[index].as_ref()
    }

    pub fn plugin_for_extension(&self, ext: &str) -> Option<&dyn LanguagePlugin> {
        self.plugins
            .iter()
            .find(|p| p.extensions().contains(&ext))
            .map(|p| p.as_ref())
    }

    pub fn plugin_for_path(&self, path: &Path) -> Option<&dyn LanguagePlugin> {
        let ext = path.extension().and_then(|s| s.to_str())?;
        self.plugin_for_extension(ext)
    }

    pub fn plugin_for_id(&self, id: LanguageId) -> Option<&dyn LanguagePlugin> {
        self.plugins
            .iter()
            .find(|p| p.id() == id)
            .map(|p| p.as_ref())
    }

    pub fn enabled_languages(&self) -> impl Iterator<Item = LanguageId> + '_ {
        self.plugins.iter().map(|p| p.id())
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::from_plugins(crate::lang::enabled_plugins())
    }
}
