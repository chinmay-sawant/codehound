//! Scan profiles (product packs) for high-signal defaults.

use std::collections::HashSet;

use super::scan::FailPolicy;

/// Named product pack. CLI default is [`ScanProfile::Recommended`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScanProfile {
    /// Curated CI pack: S-tier PERF + taint-core CWEs. BP off. Fail high.
    #[default]
    Recommended,
    /// Framework + hot-path PERF (broader than recommended). BP off.
    Perf,
    /// Taint CWE core + high-value structural CWEs. Taint on. BP off.
    Security,
    /// Bad-practice / style pack only (advisory).
    Style,
    /// Full catalog (explicit opt-in for “everything”).
    All,
}

impl ScanProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recommended => "recommended",
            Self::Perf => "perf",
            Self::Security => "security",
            Self::Style => "style",
            Self::All => "all",
        }
    }

    /// Parse profile name (case-insensitive). Accepts `bp` as alias for `style`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "recommended" | "default" | "ci" => Some(Self::Recommended),
            "perf" | "performance" => Some(Self::Perf),
            "security" | "sec" => Some(Self::Security),
            "style" | "bp" | "bad-practices" | "bad_practices" => Some(Self::Style),
            "all" | "full" => Some(Self::All),
            _ => None,
        }
    }

    /// Default fail policy for this profile when the user did not set CLI fail flags.
    pub fn default_fail_policy(self) -> FailPolicy {
        match self {
            Self::Recommended | Self::Security | Self::Perf => FailPolicy::Strict,
            Self::Style => FailPolicy::NoFail,
            Self::All => FailPolicy::MediumAsErrors,
        }
    }

    /// Whether taint should be enabled for this profile (unless CLI overrides).
    pub fn enables_taint(self) -> bool {
        matches!(self, Self::Security)
    }

    /// Whether BP rules run for this profile (unless CLI overrides).
    pub fn enables_bad_practices(self) -> bool {
        matches!(self, Self::Style | Self::All)
    }

    /// Rule allow-list patterns for this profile.
    ///
    /// `None` means no `only` filter (full catalog, still subject to skip/BP flags).
    pub fn only_patterns(self) -> Option<&'static [&'static str]> {
        match self {
            Self::Recommended => Some(RECOMMENDED_RULES),
            Self::Perf => Some(PERF_PACK_RULES),
            Self::Security => Some(SECURITY_PACK_RULES),
            Self::Style => Some(&["BP-*"]),
            Self::All => None,
        }
    }

    /// Apply profile defaults onto an existing only/skip/fail/taint/bp setup.
    ///
    /// CLI `--only` is merged (union) with the pack when both are present.
    /// Explicit fail policy / taint / no-bp flags should be applied by the caller after this.
    pub fn apply_base(
        self,
        only: &mut Option<HashSet<String>>,
        fail_policy: &mut FailPolicy,
        cli_set_fail_policy: bool,
        taint_enabled: &mut bool,
        bad_practices_enabled: &mut bool,
        cli_set_taint: bool,
        cli_set_bp: bool,
    ) {
        if let Some(patterns) = self.only_patterns() {
            let mut pack: HashSet<String> = patterns.iter().map(|s| (*s).to_string()).collect();
            if let Some(existing) = only.take() {
                pack.extend(existing);
            }
            *only = Some(pack);
        }
        if !cli_set_fail_policy {
            *fail_policy = self.default_fail_policy();
        }
        if !cli_set_taint {
            *taint_enabled = self.enables_taint();
        }
        if !cli_set_bp {
            *bad_practices_enabled = self.enables_bad_practices();
        }
    }
}

/// S-tier PERF + taint-core CWEs (≤ ~30 rules). Directional CI default pack.
const RECOMMENDED_RULES: &[&str] = &[
    // PERF S-tier (hot-path / framework footguns)
    "PERF-1",   // regex compile in loop
    "PERF-7",   // defer in loop
    "PERF-50",  // regexp.MatchString in loop
    "PERF-58",  // Gin request body not closed
    "PERF-71",  // GORM N+1
    "PERF-101", // http.Server timeouts
    "PERF-189", // response body not drained before close
    "PERF-190", // HTTP client missing timeout
    // Taint-core CWEs (require --taint or security profile; listed so only-filter keeps them)
    "CWE-22",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-90",
    "CWE-91",
];

/// Broader PERF pack (recommended PERF + common framework/hot-path extras).
const PERF_PACK_RULES: &[&str] = &[
    "PERF-1",
    "PERF-7",
    "PERF-11",
    "PERF-12",
    "PERF-22",
    "PERF-31",
    "PERF-50",
    "PERF-58",
    "PERF-71",
    "PERF-101",
    "PERF-142",
    "PERF-143",
    "PERF-164",
    "PERF-183",
    "PERF-189",
    "PERF-190",
    "PERF-210",
    "PERF-213",
];

/// Security pack: taint core + a few structural path/injection neighbors.
/// Fixture-only CWEs are intentionally absent (see [`crate::rules::maturity`]).
const SECURITY_PACK_RULES: &[&str] = &[
    "CWE-22",
    "CWE-41",
    "CWE-59",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-90",
    "CWE-91",
    "CWE-93",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_is_small() {
        assert!(RECOMMENDED_RULES.len() <= 30);
        assert!(RECOMMENDED_RULES.contains(&"PERF-101"));
        assert!(RECOMMENDED_RULES.contains(&"CWE-22"));
        assert!(!RECOMMENDED_RULES.iter().any(|r| r.starts_with("BP-")));
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(ScanProfile::parse("ci"), Some(ScanProfile::Recommended));
        assert_eq!(ScanProfile::parse("bp"), Some(ScanProfile::Style));
        assert_eq!(ScanProfile::parse("ALL"), Some(ScanProfile::All));
    }
}
