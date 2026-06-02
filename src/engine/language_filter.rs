//! Effective language filtering (CLI, config, and walk).

use std::collections::HashSet;

use anyhow::{Result, bail};

use crate::core::LanguageId;
use crate::engine::config::SlopguardConfig;
use crate::engine::registry::Registry;

/// Which languages to include when collecting and scanning files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum LanguageFilter {
    /// All languages enabled in the binary (default).
    #[default]
    All,
    /// Single language from `--lang` (overrides config).
    One(LanguageId),
    /// Subset from `slopguard.toml` `[slopguard.languages]`.
    Many(HashSet<LanguageId>),
}

impl LanguageFilter {
    pub fn allows(&self, language: LanguageId) -> bool {
        match self {
            Self::All => true,
            Self::One(id) => language == *id,
            Self::Many(set) => set.contains(&language),
        }
    }
}

/// Resolve filter: `--lang` wins over config `languages`; empty config means all.
pub fn resolve_language_filter(
    cli_lang: Option<LanguageId>,
    config: Option<&SlopguardConfig>,
    registry: &Registry,
) -> Result<LanguageFilter> {
    if let Some(id) = cli_lang {
        return Ok(LanguageFilter::One(id));
    }

    let Some(names) = config
        .map(|c| c.slopguard.languages.as_slice())
        .filter(|s| !s.is_empty())
    else {
        return Ok(LanguageFilter::All);
    };

    let enabled: HashSet<LanguageId> = registry.enabled_languages().collect();
    let mut allowed = HashSet::new();
    for name in names {
        let Some(id) = LanguageId::from_config_name(name) else {
            let known = format_known_language_names(&enabled);
            bail!("unknown language {name:?} in slopguard.toml; expected one of: {known}");
        };
        if !enabled.contains(&id) {
            let known = format_known_language_names(&enabled);
            bail!("language {name:?} is not enabled in this build; available: {known}");
        }
        allowed.insert(id);
    }

    Ok(LanguageFilter::Many(allowed))
}

fn format_known_language_names(enabled: &HashSet<LanguageId>) -> String {
    let mut names: Vec<&str> = enabled
        .iter()
        .flat_map(|id| id.config_names().iter().copied())
        .collect();
    names.sort_unstable();
    names.dedup();
    names.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::config::SlopguardSection;

    #[test]
    fn cli_lang_overrides_config_languages() {
        let registry = Registry::default();
        let config = SlopguardConfig {
            slopguard: SlopguardSection {
                languages: vec!["python".into()],
                ..Default::default()
            },
        };
        let filter =
            resolve_language_filter(Some(LanguageId::Go), Some(&config), &registry).unwrap();
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
}
