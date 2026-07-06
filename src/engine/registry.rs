//! Detector and language plugin registry.

use std::collections::HashMap;
use std::path::Path;

use crate::core::{Detector, LanguageId, LanguagePlugin};

/// Holds enabled language plugins and detectors indexed by language.
#[must_use = "build a Registry before scanning"]
pub struct Registry {
    plugins: Vec<Box<dyn LanguagePlugin>>,
    /// File extension (no dot) → index in `plugins`.
    by_extension: HashMap<&'static str, usize>,
    /// Language id → index in `plugins`.
    by_id: HashMap<LanguageId, usize>,
    detectors: Vec<Box<dyn Detector>>,
    /// Detector indices grouped by language (avoids scanning all rules per file).
    by_language: HashMap<LanguageId, Vec<usize>>,
    /// All detector indices, cached at construction for project-level finalize.
    all_indices: Vec<usize>,
}

impl Registry {
    pub(crate) fn from_plugins(plugins: Vec<Box<dyn LanguagePlugin>>) -> Self {
        let mut by_extension = HashMap::new();
        let mut by_id = HashMap::new();
        for (idx, plugin) in plugins.iter().enumerate() {
            by_id.insert(plugin.id(), idx);
            for &ext in plugin.extensions() {
                by_extension.insert(ext, idx);
            }
        }

        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
        let mut by_language: HashMap<LanguageId, Vec<usize>> = HashMap::new();

        for plugin in &plugins {
            for det in plugin.detectors() {
                let idx = detectors.len();
                by_language.entry(det.language()).or_default().push(idx);
                detectors.push(det);
            }
        }

        let all_indices: Vec<usize> = (0..detectors.len()).collect();

        Self {
            plugins,
            by_extension,
            by_id,
            detectors,
            by_language,
            all_indices,
        }
    }

    pub fn detector_indices(&self, language: LanguageId) -> &[usize] {
        self.by_language
            .get(&language)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// All detector indices, for project-level finalize passes.
    pub fn detector_indices_for_project(&self) -> &[usize] {
        &self.all_indices
    }

    pub fn detector(&self, index: usize) -> &dyn Detector {
        self.detectors[index].as_ref()
    }

    pub fn plugin_for_extension(&self, ext: &str) -> Option<&dyn LanguagePlugin> {
        self.by_extension
            .get(ext)
            .map(|&idx| self.plugins[idx].as_ref())
    }

    pub fn plugin_for_path(&self, path: &Path) -> Option<&dyn LanguagePlugin> {
        let ext = path.extension().and_then(|s| s.to_str())?;
        self.plugin_for_extension(ext)
    }

    pub fn plugin_for_id(&self, id: LanguageId) -> Option<&dyn LanguagePlugin> {
        self.by_id.get(&id).map(|&idx| self.plugins[idx].as_ref())
    }

    pub fn enabled_languages(&self) -> impl Iterator<Item = LanguageId> + '_ {
        self.plugins.iter().map(|p| p.id())
    }

    /// Total number of detectors registered (one detector may implement many
    /// rules, see `Detector::rule_ids`).
    pub fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// All detectors in the registry, in registration order.
    pub fn detectors(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::from_plugins(crate::lang::enabled_plugins())
    }
}