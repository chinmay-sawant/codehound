//! Rule pack classification and detector timing policy.
//!
//! Pack membership drives product-profile filters and BP enablement; timing
//! granularity drives how the walk layer attributes debug spans. Both are
//! typed metadata rather than ad-hoc `starts_with("BP-")` / `"PERF-"` checks.

use serde::Serialize;

/// Product / catalog pack a rule or detector belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePack {
    /// Bad-practice / style heuristics (`BP-*`).
    BadPractice,
    /// Performance heuristics (`PERF-*`).
    Performance,
    /// Security / CWE heuristics (`CWE-*`).
    Security,
    /// Uncategorized or language-specific rules.
    General,
}

impl RulePack {
    /// Classify a rule id into a pack.
    ///
    /// Known families use stable id prefixes as the catalog convention; unknown
    /// ids fall into [`RulePack::General`]. Prefer reading
    /// [`crate::rules::RuleMetadata::pack`] or [`crate::core::Detector::pack`]
    /// when a metadata or detector handle is available.
    #[must_use]
    pub const fn from_rule_id(rule_id: &str) -> Self {
        // const-friendly prefix checks (no `starts_with` on &str in const on
        // older MSRV paths — use byte compares for the known short prefixes).
        let b = rule_id.as_bytes();
        if b.len() >= 3 && b[0] == b'B' && b[1] == b'P' && b[2] == b'-' {
            return Self::BadPractice;
        }
        if b.len() >= 5
            && b[0] == b'P'
            && b[1] == b'E'
            && b[2] == b'R'
            && b[3] == b'F'
            && b[4] == b'-'
        {
            return Self::Performance;
        }
        if b.len() >= 4 && b[0] == b'C' && b[1] == b'W' && b[2] == b'E' && b[3] == b'-' {
            return Self::Security;
        }
        Self::General
    }

    /// Coarse category string used by reporters and `--list-rules`.
    #[must_use]
    pub const fn category_str(self) -> &'static str {
        match self {
            Self::BadPractice => "bad_practice",
            Self::Performance => "performance",
            Self::Security => "security",
            Self::General => "general",
        }
    }

    /// Whether this pack is the bad-practice / style family.
    #[must_use]
    pub const fn is_bad_practice(self) -> bool {
        matches!(self, Self::BadPractice)
    }

    /// Glob pattern for “all rules in this pack” allow/skip lists (`BP-*`, …).
    #[must_use]
    pub const fn only_glob(self) -> Option<&'static str> {
        match self {
            Self::BadPractice => Some("BP-*"),
            Self::Performance => Some("PERF-*"),
            Self::Security => Some("CWE-*"),
            Self::General => None,
        }
    }
}

/// How a detector attributes debug timing spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimingGranularity {
    /// Multi-rule pack that records its own per-rule spans via the engine’s
    /// active timing collector (`measure_active`). The walk layer must not wrap
    /// the detector in an outer pack span (would double-count).
    PerRuleSelfTimed,
    /// Multi-rule pack timed as one outer span with a stable detector label.
    DetectorSpan,
    /// Single-rule detector; span name is the rule id.
    SingleRule,
}

impl TimingGranularity {
    /// Default granularity from a detector’s rule-id list (no self-timing).
    #[must_use]
    pub const fn from_rule_count(rule_count: usize) -> Self {
        if rule_count > 1 {
            Self::DetectorSpan
        } else {
            Self::SingleRule
        }
    }
}

/// Declare a PERF tier as parallel numeric ids and `PERF-N` rule id strings.
///
/// Product packs ([`crate::core::ScanProfile`]) consume the rule-id slices;
/// Go severity policy consumes the numeric slices via
/// `lang::go::detectors::perf::tiers` re-exports so membership is not duplicated
/// by hand.
macro_rules! define_perf_tier {
    ($nums:ident, $rules:ident, $($n:literal),+ $(,)?) => {
        /// Numeric PERF ids for this tier.
        pub const $nums: &[u32] = &[$($n),+];
        /// `PERF-N` rule ids for this tier (product-pack allow-lists).
        pub const $rules: &[&str] = &[$(concat!("PERF-", stringify!($n))),+];
    };
}

define_perf_tier!(
    PERF_TIER_S_IDS,
    PERF_TIER_S_RULES,
    1,
    7,
    50,
    58,
    71,
    101,
    103,
    189,
    190
);

define_perf_tier!(
    PERF_TIER_A_IDS,
    PERF_TIER_A_RULES,
    11,
    12,
    22,
    31,
    82,
    85,
    142,
    143,
    164,
    183,
    210,
    213
);

/// Taint-core CWE ids shared by recommended and security packs.
pub const TAINT_CORE_CWE_RULES: &[&str] =
    &["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91"];

/// Security pack: taint core + high-value structural neighbors.
pub const SECURITY_PACK_RULES: &[&str] = &[
    "CWE-22", "CWE-41", "CWE-59", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-93",
];

/// Style-pack allow pattern (all bad-practice rules).
pub const STYLE_PACK_PATTERNS: &[&str] = match RulePack::BadPractice.only_glob() {
    Some(glob) => &[glob],
    None => &[],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_known_prefixes() {
        assert_eq!(RulePack::from_rule_id("BP-1"), RulePack::BadPractice);
        assert_eq!(RulePack::from_rule_id("PERF-101"), RulePack::Performance);
        assert_eq!(RulePack::from_rule_id("CWE-22"), RulePack::Security);
        assert_eq!(RulePack::from_rule_id("SLOP101"), RulePack::General);
    }

    #[test]
    fn only_globs() {
        assert_eq!(RulePack::BadPractice.only_glob(), Some("BP-*"));
        assert_eq!(RulePack::Performance.only_glob(), Some("PERF-*"));
        assert_eq!(RulePack::Security.only_glob(), Some("CWE-*"));
        assert_eq!(RulePack::General.only_glob(), None);
    }

    #[test]
    fn style_pack_patterns_use_bp_glob() {
        assert_eq!(STYLE_PACK_PATTERNS, &["BP-*"]);
    }

    #[test]
    fn perf_tier_rule_ids_match_numeric_ids() {
        assert_eq!(PERF_TIER_S_IDS.len(), PERF_TIER_S_RULES.len());
        for (n, id) in PERF_TIER_S_IDS.iter().zip(PERF_TIER_S_RULES) {
            assert_eq!(*id, format!("PERF-{n}"));
        }
        assert_eq!(PERF_TIER_A_IDS.len(), PERF_TIER_A_RULES.len());
        for (n, id) in PERF_TIER_A_IDS.iter().zip(PERF_TIER_A_RULES) {
            assert_eq!(*id, format!("PERF-{n}"));
        }
    }
}
