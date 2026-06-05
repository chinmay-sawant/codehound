//! Optional `slopguard.toml` configuration.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::core::{FailPolicy, ScanContext};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlopguardConfig {
    #[serde(default)]
    pub slopguard: SlopguardSection,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlopguardSection {
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub skip: Vec<String>,
    #[serde(default)]
    pub only: Vec<String>,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl SlopguardConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).context("parsing slopguard.toml")
    }

    pub fn discover() -> Option<Self> {
        load_discovered_config().ok().flatten()
    }

    /// Merge this config into a `ScanContext`. CLI-set fields take precedence:
    /// `skip` and `only` are merged additively (config adds to CLI), but
    /// `fail_policy` is only applied when the CLI did not pass an explicit
    /// one (signaled by `cli_set_fail_policy`).
    pub fn merge_into(self, mut ctx: ScanContext, cli_set_fail_policy: bool) -> ScanContext {
        if !self.slopguard.skip.is_empty() {
            ctx.skip.extend(self.slopguard.skip);
        }
        if !self.slopguard.only.is_empty() {
            ctx.only = Some(self.slopguard.only.into_iter().collect());
        }
        if let Some(fail_on) = self.slopguard.fail_on.as_deref() {
            if !cli_set_fail_policy {
                ctx.fail_policy = fail_on_to_policy(fail_on);
            }
        }
        ctx
    }

    pub fn include(&self) -> &[String] {
        &self.slopguard.include
    }

    pub fn exclude(&self) -> &[String] {
        &self.slopguard.exclude
    }
}

#[doc(hidden)]
pub fn fail_on_to_policy(s: &str) -> FailPolicy {
    match s.to_lowercase().as_str() {
        "none" | "never" => FailPolicy::NoFail,
        "high" | "strict" => FailPolicy::Strict,
        _ => FailPolicy::WarningsAsErrors,
    }
}

/// Walk from `start` upward looking for the closest `slopguard.toml`.
pub fn discover_config(start: &Path) -> Option<std::path::PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join("slopguard.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Load `slopguard.toml` from the current directory when present.
pub fn load_discovered_config() -> Result<Option<SlopguardConfig>> {
    let path = Path::new("slopguard.toml");
    if path.is_file() {
        Ok(Some(SlopguardConfig::load(path)?))
    } else {
        Ok(None)
    }
}

/// Build scan context from CLI + optional config file.
pub fn build_scan_context(
    only: Vec<String>,
    skip: Vec<String>,
    fail_policy: FailPolicy,
    config: Option<SlopguardConfig>,
    cli_set_fail_policy: bool,
) -> ScanContext {
    let mut ctx = ScanContext {
        only: if only.is_empty() {
            None
        } else {
            Some(only.into_iter().collect())
        },
        skip: skip.into_iter().collect(),
        fail_policy,
    };
    if let Some(cfg) = config {
        ctx = cfg.merge_into(ctx, cli_set_fail_policy);
    }
    ctx
}

