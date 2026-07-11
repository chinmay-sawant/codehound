//! Rule maturity tags for catalog honesty and pack membership.

/// How trustworthy / general a rule is for production CI packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum RuleMaturity {
    /// Graph-based injection/XSS family (taint).
    TaintCore,
    /// AST/facts with generalized patterns.
    Structural,
    /// Useful smell, higher FP rate.
    Heuristic,
    /// Encodes test corpus strings; never in recommended/security.
    FixtureOnly,
    /// Placeholder / reserved; disabled outside `all`.
    Reserved,
}

impl RuleMaturity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TaintCore => "taint-core",
            Self::Structural => "structural",
            Self::Heuristic => "heuristic",
            Self::FixtureOnly => "fixture-only",
            Self::Reserved => "reserved",
        }
    }

    /// Allowed in recommended or security packs.
    pub fn allowed_in_default_packs(self) -> bool {
        matches!(self, Self::TaintCore | Self::Structural | Self::Heuristic)
    }
}

/// Look up maturity for a rule ID. Unknown rules default to [`RuleMaturity::Heuristic`].
pub fn maturity_for(rule_id: &str) -> RuleMaturity {
    if is_fixture_only(rule_id) {
        return RuleMaturity::FixtureOnly;
    }
    if is_reserved(rule_id) {
        return RuleMaturity::Reserved;
    }
    if is_taint_core(rule_id) {
        return RuleMaturity::TaintCore;
    }
    if is_structural_cwe(rule_id) {
        return RuleMaturity::Structural;
    }
    RuleMaturity::Heuristic
}

/// True if this rule must never appear in recommended/security packs.
pub fn is_quarantined_from_default_packs(rule_id: &str) -> bool {
    !maturity_for(rule_id).allowed_in_default_packs()
}

fn is_taint_core(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "CWE-22" | "CWE-78" | "CWE-79" | "CWE-89" | "CWE-90" | "CWE-91"
    )
}

fn is_structural_cwe(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "CWE-41" | "CWE-59" | "CWE-76" | "CWE-93" | "CWE-112" | "CWE-22"
    )
}

/// Rules known to encode fixture-only needles (magic numbers, exact ids, PRNG museum).
/// Expand as audits land; keep sorted for review.
fn is_fixture_only(rule_id: &str) -> bool {
    matches!(
        rule_id,
        // PRNG / token fixture museum (see domains/cryptography/prng.rs)
        "CWE-334"
            | "CWE-335"
            | "CWE-338"
            | "CWE-342"
            | "CWE-343"
            // Common fixture-shaped long-tail (path/corpus strings)
            | "CWE-798" // hard-coded credentials often fixture-shaped
    )
}

fn is_reserved(rule_id: &str) -> bool {
    // BP reserved slots / empty CVE feed placeholders when present.
    matches!(rule_id, "BP-63" | "BP-64" | "BP-65")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_only_quarantined() {
        assert_eq!(maturity_for("CWE-334"), RuleMaturity::FixtureOnly);
        assert!(is_quarantined_from_default_packs("CWE-334"));
        assert!(!is_quarantined_from_default_packs("CWE-22"));
        assert!(!is_quarantined_from_default_packs("PERF-101"));
    }

    #[test]
    fn taint_core_tagged() {
        assert_eq!(maturity_for("CWE-89"), RuleMaturity::TaintCore);
    }
}
