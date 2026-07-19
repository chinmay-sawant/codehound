//! Detector and language plugin registry.

use std::collections::HashMap;
use std::path::Path;

use crate::core::{Detector, LanguageId, LanguagePlugin};

/// Invalid plugin composition supplied to [`Registry::with_plugins`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    /// Two plugins claimed the same language identifier.
    #[error("duplicate language plugin: {language:?}")]
    DuplicateLanguage {
        /// Language claimed by more than one plugin.
        language: LanguageId,
    },
    /// Two plugins claimed the same file extension.
    #[error("extension {extension:?} is registered by more than one plugin")]
    DuplicateExtension {
        /// Extension claimed by more than one plugin.
        extension: &'static str,
    },
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
    /// Each plugin’s [`LanguagePlugin::detectors`] factory is invoked **once**:
    /// the resulting records are validated, then indexed. Plugins must not rely
    /// on the factory running more than once per registry construction.
    ///
    /// # Errors
    ///
    /// Returns a typed error when language ids or extensions collide, or when
    /// a detector is registered under a different language than its plugin.
    pub fn with_plugins(plugins: Vec<Box<dyn LanguagePlugin>>) -> Result<Self, RegistryError> {
        let prepared = materialize_plugins(plugins)?;
        Ok(Self::from_prepared(prepared))
    }

    pub(crate) fn from_plugins(plugins: Vec<Box<dyn LanguagePlugin>>) -> Self {
        // Production path: plugins are known-good from `enabled_plugins()`.
        // Materialize once (same path as `with_plugins`) so factories are single-shot.
        match materialize_plugins(plugins) {
            Ok(prepared) => Self::from_prepared(prepared),
            Err(err) => {
                // Built-in composition is an invariant; typed error is only for
                // embedder `with_plugins`. Log and return an empty registry so
                // we never panic on the Default path.
                tracing::error!(error = %err, "built-in language plugin materialization failed");
                Self {
                    plugins: Vec::new(),
                    by_extension: HashMap::new(),
                    by_id: HashMap::new(),
                    detectors: Vec::new(),
                    by_language: HashMap::new(),
                    all_indices: Vec::new(),
                }
            }
        }
    }

    fn from_prepared(prepared: PreparedPlugins) -> Self {
        let PreparedPlugins {
            plugins,
            plugin_detectors,
        } = prepared;

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

        for dets in plugin_detectors {
            for det in dets {
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

    /// Indices of detectors registered for `language`.
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

    /// Resolve the language plugin for a file path by extension.
    pub fn plugin_for_path(&self, path: &Path) -> Option<&dyn LanguagePlugin> {
        let ext = path.extension().and_then(|s| s.to_str())?;
        self.by_extension
            .get(ext)
            .map(|&idx| self.plugins[idx].as_ref())
    }

    /// Resolve the language plugin for a language id.
    pub fn plugin_for_id(&self, id: LanguageId) -> Option<&dyn LanguagePlugin> {
        self.by_id.get(&id).map(|&idx| self.plugins[idx].as_ref())
    }

    /// Iterate language ids with registered plugins.
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

struct PreparedPlugins {
    plugins: Vec<Box<dyn LanguagePlugin>>,
    /// Detectors materialized once per plugin, in plugin order.
    plugin_detectors: Vec<Vec<Box<dyn Detector>>>,
}

/// Invoke each plugin’s detector factory once, validate language/extension
/// uniqueness and detector–plugin language match, then return the records for
/// indexing.
fn materialize_plugins(
    plugins: Vec<Box<dyn LanguagePlugin>>,
) -> Result<PreparedPlugins, RegistryError> {
    let mut by_id = HashMap::new();
    let mut by_extension = HashMap::new();
    let mut plugin_detectors = Vec::with_capacity(plugins.len());

    for plugin in &plugins {
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
        // Single materialization of this plugin’s detectors.
        let detectors = plugin.detectors();
        for detector in &detectors {
            if detector.language() != plugin.id() {
                return Err(RegistryError::DetectorLanguageMismatch {
                    plugin_language: plugin.id(),
                    detector_language: detector.language(),
                });
            }
        }
        plugin_detectors.push(detectors);
    }

    Ok(PreparedPlugins {
        plugins,
        plugin_detectors,
    })
}

impl Default for Registry {
    fn default() -> Self {
        Self::from_plugins(crate::lang::enabled_plugins())
    }
}

#[cfg(test)]
mod tests {
    use super::{Registry, RegistryError};
    use crate::core::{Detector, LanguageId, LanguagePlugin, ParsedUnit, ScanContext};
    use crate::rules::Finding;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    /// Counts how many times the detector factory runs.
    struct CountingPlugin {
        factory_calls: Arc<AtomicUsize>,
    }

    impl LanguagePlugin for CountingPlugin {
        fn id(&self) -> LanguageId {
            // Distinct from Go so we can compose with GoPlugin in other tests.
            LanguageId::Python
        }

        fn extensions(&self) -> &'static [&'static str] {
            &["counting-plugin-ext"]
        }

        fn configure_parser(&self, _parser: &mut tree_sitter::Parser) -> Result<(), crate::Error> {
            Ok(())
        }

        fn parse_with(
            &self,
            _parser: &mut tree_sitter::Parser,
            _path: &Path,
            _source: Arc<str>,
        ) -> Result<ParsedUnit, crate::Error> {
            Err(crate::Error::Parse {
                path: "<counting-plugin>".into(),
                detail: "not implemented".into(),
            })
        }

        fn detectors(&self) -> Vec<Box<dyn Detector>> {
            self.factory_calls.fetch_add(1, Ordering::SeqCst);
            vec![Box::new(NoopDetector)]
        }

        fn loop_node_kinds(&self) -> &'static [&'static str] {
            &[]
        }
    }

    struct NoopDetector;

    impl Detector for NoopDetector {
        fn language(&self) -> LanguageId {
            LanguageId::Python
        }

        fn rule_ids(&self) -> &'static [&'static str] {
            &["TEST-COUNT"]
        }

        fn run(&self, _ctx: &ScanContext, _unit: &ParsedUnit, _out: &mut Vec<Finding>) {}
    }

    #[test]
    fn plugin_detectors_factory_runs_once_during_registry_construction() {
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let plugin = CountingPlugin {
            factory_calls: Arc::clone(&factory_calls),
        };

        let registry = Registry::with_plugins(vec![Box::new(plugin)]).expect("registry builds");

        assert_eq!(
            factory_calls.load(Ordering::SeqCst),
            1,
            "LanguagePlugin::detectors must be invoked exactly once per plugin"
        );
        assert_eq!(registry.detector_count(), 1);
        assert_eq!(
            registry.detector(0).expect("detector present").rule_ids(),
            &["TEST-COUNT"]
        );
    }
}
