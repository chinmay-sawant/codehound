//! `SlopguardConfig` impl: load, discover, merge_into, and the field
//! accessors used by `app/run.rs`.

use std::path::PathBuf;

use crate::Error;
use crate::core::ScanContext;

use super::types::SlopguardConfig;

impl SlopguardConfig {
    /// Load and parse a `slopguard.toml` file from `path`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the file cannot be read and [`Error::Config`]
    /// when the TOML is invalid or contains unknown fields (serde `deny_unknown_fields`).
    #[must_use = "config load failures must be handled"]
    pub fn load(path: &std::path::Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path).map_err(Error::from)?;
        toml::from_str(&text).map_err(|e| Error::Config(format!("parsing {}: {e}", path.display())))
    }

    pub fn discover() -> Option<Self> {
        super::discover::load_discovered_config().ok().flatten()
    }

    /// Merge this config into a `ScanContext`. CLI-set fields take precedence:
    /// `skip` and `only` are merged additively, but
    /// `fail_policy` is only applied when the CLI did not pass an explicit
    /// one (signaled by `cli_set_fail_policy`).
    pub fn merge_into(self, mut ctx: ScanContext, cli_set_fail_policy: bool) -> ScanContext {
        if !self.slopguard.skip.is_empty() {
            ctx.skip.extend(self.slopguard.skip);
        }
        if !self.slopguard.only.is_empty() {
            let mut only = ctx.only.take().unwrap_or_default();
            only.extend(self.slopguard.only);
            ctx.only = Some(only);
        }
        if let Some(fail_on) = self.slopguard.fail_on.as_deref() {
            if !cli_set_fail_policy {
                ctx.fail_policy = super::discover::fail_on_to_policy(fail_on);
            }
        }
        ctx.taint_enabled = self.slopguard.taint.enabled;
        ctx.taint_show_paths = self.slopguard.taint.show_paths;
        ctx.bad_practices_enabled = self.slopguard.bad_practices.enabled;
        ctx.bad_practice_severity = self.slopguard.bad_practices.severity;
        ctx
    }

    pub fn include(&self) -> &[String] {
        &self.slopguard.include
    }

    pub fn exclude(&self) -> &[String] {
        &self.slopguard.exclude
    }

    pub fn path_filters(&self) -> super::types::PathFilters {
        super::types::PathFilters {
            include: self.slopguard.include.clone(),
            exclude: self.slopguard.exclude.clone(),
            exclude_tests: self.slopguard.exclude_tests.unwrap_or(true),
        }
    }

    pub fn baseline_enabled(&self) -> bool {
        self.slopguard.baseline.enabled
    }

    pub fn baseline_path(&self) -> Option<PathBuf> {
        self.slopguard.baseline.path.clone()
    }

    /// `false` only when the user explicitly disabled the cache in
    /// `slopguard.toml`. Default is `true` (cache on).
    pub fn cache_enabled(&self) -> bool {
        self.slopguard.cache.enabled
    }

    /// Custom cache directory, if any. When `None`, the caller is
    /// responsible for auto-discovery (or the CLI-provided override).
    pub fn cache_path(&self) -> Option<PathBuf> {
        self.slopguard.cache.path.clone()
    }

    /// True when experimental taint tracking is enabled.
    pub fn taint_enabled(&self) -> bool {
        self.slopguard.taint.enabled
    }

    /// True when taint paths should be emitted in evidence.
    pub fn taint_show_paths(&self) -> bool {
        self.slopguard.taint.show_paths
    }

    /// True when bad-practice rules are enabled.
    pub fn bad_practices_enabled(&self) -> bool {
        self.slopguard.bad_practices.enabled
    }

    /// Optional severity override for bad-practice rules.
    pub fn bad_practice_severity(&self) -> Option<crate::rules::Severity> {
        self.slopguard.bad_practices.severity
    }
}
