//! Scan profiles (product packs) for high-signal defaults.

use std::collections::HashSet;

use crate::rules::{
    PERF_TIER_A_RULES, PERF_TIER_S_RULES, SECURITY_PACK_RULES, STYLE_PACK_PATTERNS,
    TAINT_CORE_CWE_RULES,
};

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
    /// Stable lowercase profile name used in CLI/config.
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

    /// Opinion / low-value BP rules skipped by default in the style pack.
    ///
    /// Opt back in with `--only BP-28` (and friends) under `--profile style`, or
    /// by clearing skip via config. Recommended never enables BP at all.
    pub fn style_default_skip(self) -> &'static [&'static str] {
        match self {
            Self::Style => STYLE_DEFAULT_SKIP,
            _ => &[],
        }
    }

    /// Rule allow-list pattern groups for this profile.
    ///
    /// Each inner slice is unioned into the allow-list. `None` means no `only`
    /// filter (full catalog, still subject to skip/BP flags).
    pub fn only_pattern_groups(self) -> Option<&'static [&'static [&'static str]]> {
        match self {
            Self::Recommended => Some(&[PERF_TIER_S_RULES, TAINT_CORE_CWE_RULES]),
            Self::Perf => Some(&[PERF_TIER_S_RULES, PERF_TIER_A_RULES]),
            Self::Security => Some(&[SECURITY_PACK_RULES]),
            Self::Style => Some(&[STYLE_PACK_PATTERNS]),
            Self::All => None,
        }
    }

    /// Rule allow-list patterns for this profile (flattened view for tests).
    ///
    /// `None` means no `only` filter (full catalog, still subject to skip/BP flags).
    pub fn only_patterns(self) -> Option<Vec<&'static str>> {
        self.only_pattern_groups().map(|groups| {
            groups
                .iter()
                .flat_map(|g| g.iter().copied())
                .collect::<Vec<_>>()
        })
    }

    /// Apply profile defaults onto an existing only/skip/fail/taint/bp setup.
    ///
    /// CLI `--only` is merged (union) with the pack when both are present.
    /// Explicit fail policy / taint / no-bp flags should be applied by the caller after this.
    pub fn apply_base(self, target: ProfileApplyTarget<'_>) {
        if let Some(groups) = self.only_pattern_groups() {
            let mut pack: HashSet<String> = HashSet::new();
            for group in groups {
                pack.extend(group.iter().map(|s| (*s).to_string()));
            }
            if let Some(existing) = target.only.take() {
                pack.extend(existing);
            }
            *target.only = Some(pack);
        }
        if !target.cli_set_fail_policy {
            *target.fail_policy = self.default_fail_policy();
        }
        if !target.cli_set_taint {
            *target.taint_enabled = self.enables_taint();
        }
        if !target.cli_set_bp {
            *target.bad_practices_enabled = self.enables_bad_practices();
        }
    }
}

/// Mutable knobs updated when applying a [`ScanProfile`].
pub struct ProfileApplyTarget<'a> {
    /// Rule allow-list; pack patterns are unioned with any existing entries.
    pub only: &'a mut Option<HashSet<String>>,
    /// Exit policy; overwritten unless `cli_set_fail_policy` is set.
    pub fail_policy: &'a mut FailPolicy,
    /// When true, leave `fail_policy` unchanged (CLI already chose).
    pub cli_set_fail_policy: bool,
    /// Whether taint analysis runs.
    pub taint_enabled: &'a mut bool,
    /// Whether bad-practice rules run.
    pub bad_practices_enabled: &'a mut bool,
    /// When true, leave `taint_enabled` unchanged.
    pub cli_set_taint: bool,
    /// When true, leave `bad_practices_enabled` unchanged.
    pub cli_set_bp: bool,
}

/// Default-off under `--profile style` (opt-in noise / opinion).
/// BP-21: missing `t.Parallel` is policy, not correctness — off in recommended
/// already; keep out of style defaults too.
/// BP-28: single-method interfaces are an opinionated API style choice.
/// BP-30: external implementations and capability interfaces cannot be
/// distinguished from a same-package implementation scan.
const STYLE_DEFAULT_SKIP: &[&str] = &["BP-21", "BP-28", "BP-30"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RulePack;

    #[test]
    fn recommended_is_small() {
        let patterns = ScanProfile::Recommended
            .only_patterns()
            .expect("recommended has only filter");
        assert!(patterns.len() <= 30);
        assert!(patterns.contains(&"PERF-101"));
        assert!(patterns.contains(&"CWE-22"));
        assert!(
            !patterns
                .iter()
                .any(|r| RulePack::from_rule_id(r).is_bad_practice())
        );
    }

    #[test]
    fn recommended_perf_matches_s_tier_metadata() {
        let patterns = ScanProfile::Recommended
            .only_patterns()
            .expect("recommended has only filter");
        for id in PERF_TIER_S_RULES {
            assert!(patterns.contains(id), "missing {id} in recommended");
        }
        let perf_count = patterns
            .iter()
            .filter(|r| RulePack::from_rule_id(r) == RulePack::Performance)
            .count();
        assert_eq!(perf_count, PERF_TIER_S_RULES.len());
    }

    #[test]
    fn perf_profile_is_s_plus_a() {
        let patterns = ScanProfile::Perf
            .only_patterns()
            .expect("perf has only filter");
        assert_eq!(
            patterns.len(),
            PERF_TIER_S_RULES.len() + PERF_TIER_A_RULES.len()
        );
        for id in PERF_TIER_A_RULES {
            assert!(patterns.contains(id), "missing {id} in perf pack");
        }
    }

    #[test]
    fn style_uses_bad_practice_pack_glob() {
        let patterns = ScanProfile::Style
            .only_patterns()
            .expect("style has only filter");
        assert_eq!(
            patterns,
            vec![RulePack::BadPractice.only_glob().expect("BP glob")]
        );
    }

    #[test]
    fn parse_aliases() {
        assert_eq!(ScanProfile::parse("ci"), Some(ScanProfile::Recommended));
        assert_eq!(ScanProfile::parse("bp"), Some(ScanProfile::Style));
        assert_eq!(ScanProfile::parse("ALL"), Some(ScanProfile::All));
    }

    #[test]
    fn style_skips_opinion_rules() {
        assert!(ScanProfile::Style.style_default_skip().contains(&"BP-21"));
        assert!(ScanProfile::Style.style_default_skip().contains(&"BP-28"));
        assert!(ScanProfile::Style.style_default_skip().contains(&"BP-30"));
        assert!(ScanProfile::Recommended.style_default_skip().is_empty());
    }
}
