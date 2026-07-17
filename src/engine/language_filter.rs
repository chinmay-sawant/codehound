//! Effective language filtering (CLI, config, and walk).

use std::collections::HashSet;

use crate::Error;
use crate::core::LanguageId;
use crate::engine::config::CodehoundConfig;
use crate::engine::registry::Registry;

/// Which languages to include when collecting and scanning files.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum LanguageFilter {
    /// All languages enabled in the binary (default).
    #[default]
    All,
    /// Single language from `--lang` (overrides config).
    One(LanguageId),
    /// Subset from `codehound.toml` `[codehound.languages]`.
    Many(HashSet<LanguageId>),
}

impl LanguageFilter {
    /// Whether `language` is included by this filter.
    pub fn allows(&self, language: LanguageId) -> bool {
        match self {
            Self::All => true,
            Self::One(id) => language == *id,
            Self::Many(set) => set.contains(&language),
        }
    }
}

/// Resolve filter: `--lang` wins over config `languages`; empty config means all.
///
/// # Errors
///
/// Returns [`Error::Config`] when `codehound.toml` lists an unknown or
/// disabled language for this build.
#[must_use = "language filter resolution failures must be handled"]
pub fn resolve_language_filter(
    cli_lang: Option<LanguageId>,
    config: Option<&CodehoundConfig>,
    registry: &Registry,
) -> Result<LanguageFilter, Error> {
    if let Some(id) = cli_lang {
        return Ok(LanguageFilter::One(id));
    }

    let Some(names) = config
        .map(|c| c.codehound.languages.as_slice())
        .filter(|s| !s.is_empty())
    else {
        return Ok(LanguageFilter::All);
    };

    let enabled: HashSet<LanguageId> = registry.enabled_languages().collect();
    let mut allowed = HashSet::new();
    for name in names {
        let Some(id) = LanguageId::from_config_name(name) else {
            let known = format_known_language_names(&enabled);
            return Err(Error::Config(format!(
                "unknown language {name:?} in codehound.toml; expected one of: {known}"
            )));
        };
        if !enabled.contains(&id) {
            let known = format_known_language_names(&enabled);
            return Err(Error::Config(format!(
                "language {name:?} is not enabled in this build; available: {known}"
            )));
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
