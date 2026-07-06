use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use codehound::cli::Cli;
use codehound::engine::{CodehoundConfig, discover_baseline, discover_config};

pub(crate) fn load_config(explicit: Option<&Path>) -> Result<Option<CodehoundConfig>> {
    if let Some(path) = explicit {
        if !path.is_file() {
            anyhow::bail!("config file not found: {}", path.display());
        }
        Ok(Some(
            CodehoundConfig::load(path)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("loading config {}", path.display()))?,
        ))
    } else if let Some(found) = discover_config(Path::new(".")) {
        Ok(Some(
            CodehoundConfig::load(&found)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("loading config {}", found.display()))?,
        ))
    } else {
        Ok(None)
    }
}

pub(crate) fn baseline_loading_enabled(cli: &Cli, config: Option<&CodehoundConfig>) -> bool {
    if cli.no_baseline {
        return false;
    }
    config.is_none_or(|cfg| cfg.codehound.baseline.enabled)
}

pub(crate) fn baseline_load_path(cli: &Cli, config: Option<&CodehoundConfig>) -> Option<PathBuf> {
    cli.baseline_file
        .clone()
        .or_else(|| config.and_then(|cfg| cfg.codehound.baseline.path.clone()))
        .or_else(|| discover_baseline(Path::new(".")))
}
