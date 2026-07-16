//! Detector and language plugin registry.

use std::collections::HashMap;
use std::path::Path;

use crate::core::{Detector, LanguageId, LanguagePlugin};

/// Invalid plugin composition supplied to [`Registry::with_plugins`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    /// Two plugins claimed the same language identifier.
    #[error("duplicate language plugin: {language:?}")]
    DuplicateLanguage { language: LanguageId },
    /// Two plugins claimed the same file extension.
    #[error("extension {extension:?} is registered by more than one plugin")]
    DuplicateExtension { extension: &'static str },
    /// A plugin returned a detector for a different language.
    #[error(
        "detector language {detector_language:?} does not match plugin language {plugin_language:?}"
    )]
    DetectorLanguageMismatch {
        /// Language declared by the containing plugin.
        plugin_language: LanguageId,
        /// Language declared by the detector.
        detector_language: LanguageId,
    },
}

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
    /// Build a registry from an explicit plugin list (embedder / test seam).
    ///
    /// # Errors
    ///
    /// Returns a typed error when language ids or extensions collide, or when
    /// a detector is registered under a different language than its plugin.
    pub fn with_plugins(plugins: Vec<Box<dyn LanguagePlugin>>) -> Result<Self, RegistryError> {
        validate_plugins(&plugins)?;
        Ok(Self::from_plugins(plugins))
    }

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

    /// Return a detector for an index from [`Self::detector_indices`].
    /// Invalid external indices are reported as `None` instead of panicking.
    pub fn detector(&self, index: usize) -> Option<&dyn Detector> {
        self.detectors.get(index).map(|detector| detector.as_ref())
    }

    pub fn plugin_for_path(&self, path: &Path) -> Option<&dyn LanguagePlugin> {
        let ext = path.extension().and_then(|s| s.to_str())?;
        self.by_extension
            .get(ext)
            .map(|&idx| self.plugins[idx].as_ref())
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

fn validate_plugins(plugins: &[Box<dyn LanguagePlugin>]) -> Result<(), RegistryError> {
    let mut by_id = HashMap::new();
    let mut by_extension = HashMap::new();
    for plugin in plugins {
        if by_id.insert(plugin.id(), ()).is_some() {
            return Err(RegistryError::DuplicateLanguage {
                language: plugin.id(),
            });
        }
        for &extension in plugin.extensions() {
            if by_extension.insert(extension, ()).is_some() {
                return Err(RegistryError::DuplicateExtension { extension });
            }
        }
        for detector in plugin.detectors() {
            if detector.language() != plugin.id() {
                return Err(RegistryError::DetectorLanguageMismatch {
                    plugin_language: plugin.id(),
                    detector_language: detector.language(),
                });
            }
        }
    }
    Ok(())
}

impl Default for Registry {
    fn default() -> Self {
        Self::from_plugins(crate::lang::enabled_plugins())
    }
}

#[cfg(test)]
mod tests {
    use super::{Registry, RegistryError};

    #[test]
    fn explicit_registry_rejects_duplicate_language_plugins() {
        let result = Registry::with_plugins(vec![
            Box::new(crate::lang::go::GoPlugin),
            Box::new(crate::lang::go::GoPlugin),
        ]);

        assert!(matches!(
            result,
            Err(RegistryError::DuplicateLanguage { .. })
        ));
    }
}
