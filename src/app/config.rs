use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use slopguard::cli::Cli;
use slopguard::engine::{SlopguardConfig, discover_baseline, discover_config};

pub fn load_config(explicit: Option<&Path>) -> Result<Option<SlopguardConfig>> {
    if let Some(path) = explicit {
        if !path.is_file() {
            anyhow::bail!("config file not found: {}", path.display());
        }
        Ok(Some(
            SlopguardConfig::load(path)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("loading config {}", path.display()))?,
        ))
    } else if let Some(found) = discover_config(Path::new(".")) {
        Ok(Some(
            SlopguardConfig::load(&found)
                .map_err(anyhow::Error::from)
                .with_context(|| format!("loading config {}", found.display()))?,
        ))
    } else {
        Ok(None)
    }
}

pub(crate) fn baseline_loading_enabled(cli: &Cli, config: Option<&SlopguardConfig>) -> bool {
    if cli.no_baseline {
        return false;
    }
    config.is_none_or(SlopguardConfig::baseline_enabled)
}

pub(crate) fn baseline_load_path(cli: &Cli, config: Option<&SlopguardConfig>) -> Option<PathBuf> {
    cli.baseline_file
        .clone()
        .or_else(|| config.and_then(SlopguardConfig::baseline_path))
        .or_else(|| discover_baseline(Path::new(".")))
}
