//! `SlopguardConfig` impl: load, discover, merge_into, and the field
//! accessors used by `app/run.rs`.

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
        if let Some(enabled) = self.slopguard.taint.enabled {
            ctx.taint_enabled = enabled;
        }
        if let Some(show_paths) = self.slopguard.taint.show_paths {
            ctx.taint_show_paths = show_paths;
        }
        ctx.bad_practices_enabled = self.slopguard.bad_practices.enabled;
        ctx.bad_practice_severity = self.slopguard.bad_practices.severity;
        ctx
    }
}
