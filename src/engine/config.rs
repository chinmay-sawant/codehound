//! Optional `slopguard.toml` configuration.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::core::{FailPolicy, ScanContext};
use crate::rules::Severity;

#[derive(Debug, Default, Deserialize)]
pub struct SlopguardConfig {
    #[serde(default)]
    pub slopguard: SlopguardSection,
}

#[derive(Debug, Default, Deserialize)]
pub struct SlopguardSection {
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub skip: Vec<String>,
    #[serde(default)]
    pub only: Vec<String>,
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

    pub fn merge_into(self, mut ctx: ScanContext) -> ScanContext {
        if !self.slopguard.skip.is_empty() {
            ctx.skip.extend(self.slopguard.skip);
        }
        if !self.slopguard.only.is_empty() {
            ctx.only = Some(self.slopguard.only.into_iter().collect());
        }
        if let Some(fail_on) = self.slopguard.fail_on.as_deref() {
            ctx.fail_policy = fail_on_to_policy(fail_on);
        }
        ctx
    }
}

fn fail_on_to_policy(s: &str) -> FailPolicy {
    match s.to_lowercase().as_str() {
        "none" | "never" => FailPolicy::NoFail,
        "high" | "strict" => FailPolicy::Strict,
        _ => FailPolicy::WarningsAsErrors,
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
        ctx = cfg.merge_into(ctx);
    }
    ctx
}

#[allow(dead_code)]
pub fn severity_threshold(policy: FailPolicy) -> Severity {
    match policy {
        FailPolicy::Strict => Severity::High,
        FailPolicy::NoFail => Severity::Info,
        FailPolicy::WarningsAsErrors => Severity::Warning,
    }
}
