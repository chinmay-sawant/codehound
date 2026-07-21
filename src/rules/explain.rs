//! User-facing rule explainability derived from [`crate::rules::maturity`].
//!
//! This is the single presentation layer for maturity + pack eligibility. It
//! does **not** introduce a second rule-status model — every field is computed
//! from [`maturity_for`] / [`RuleMaturity`] / [`is_quarantined_from_default_packs`].

use super::maturity::{RuleMaturity, is_quarantined_from_default_packs, maturity_for};
use super::pack::{
    PERF_TIER_A_RULES, PERF_TIER_S_RULES, SECURITY_PACK_RULES, TAINT_CORE_CWE_RULES,
};

/// Stable explainability view for a rule id.
///
/// Built only from the existing maturity registry and pack allow-lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleExplainability {
    /// Stable rule identifier (e.g. `CWE-89`).
    pub rule_id: String,
    /// Maturity tag string (`taint-core`, `structural`, …).
    pub maturity: &'static str,
    /// Whether the rule is quarantined from recommended/security/perf packs.
    pub quarantined: bool,
    /// Human-readable pack eligibility summary.
    pub pack_eligibility: &'static str,
    /// Advisory / quarantine reason (why this maturity / pack status).
    pub status_reason: &'static str,
    /// Where to read more about this maturity / pack policy.
    pub documentation: &'static str,
}

impl RuleExplainability {
    /// Build explainability fields for `rule_id` from the maturity registry.
    #[must_use]
    pub fn for_rule(rule_id: &str) -> Self {
        let maturity = maturity_for(rule_id);
        Self {
            rule_id: rule_id.to_string(),
            maturity: maturity.as_str(),
            quarantined: is_quarantined_from_default_packs(rule_id),
            pack_eligibility: pack_eligibility_for(rule_id, maturity),
            status_reason: status_reason_for(maturity),
            documentation: documentation_for(maturity),
        }
    }

    /// Format the explainability block printed by `codehound rules --explain`.
    #[must_use]
    pub fn format_block(&self) -> String {
        format!(
            "Rule ID:           {}\n\
             Maturity:          {}\n\
             Pack eligibility:  {}\n\
             Status reason:     {}\n\
             Documentation:     {}",
            self.rule_id,
            self.maturity,
            self.pack_eligibility,
            self.status_reason,
            self.documentation,
        )
    }
}

fn pack_eligibility_for(rule_id: &str, maturity: RuleMaturity) -> &'static str {
    match maturity {
        RuleMaturity::FixtureOnly => {
            "quarantined from recommended/security/perf; available under --profile all or --only (not production-certified)"
        }
        RuleMaturity::Reserved => {
            "quarantined from recommended/security/perf; available under --profile all or --only (advisory / incomplete)"
        }
        RuleMaturity::TaintCore => {
            "eligible for recommended (with --taint) and security packs; also under --profile all"
        }
        RuleMaturity::Structural => {
            if SECURITY_PACK_RULES.contains(&rule_id) {
                "eligible for security pack (structural allow-list); also under --profile all"
            } else {
                "not quarantined; pack membership follows profile allow-lists / --only"
            }
        }
        RuleMaturity::Heuristic => {
            if TAINT_CORE_CWE_RULES.contains(&rule_id) {
                // Defensive: taint-core is never Heuristic, but keep branch total.
                "eligible for recommended/security via taint-core allow-list"
            } else if PERF_TIER_S_RULES.contains(&rule_id) {
                "eligible for recommended and perf packs (S-tier PERF); also under --profile all"
            } else if PERF_TIER_A_RULES.contains(&rule_id) {
                "eligible for perf pack (A-tier PERF); also under --profile all"
            } else if rule_id.starts_with("BP-") {
                "eligible for style pack (BP-*); off under recommended/security unless --only"
            } else {
                "not quarantined from default packs; membership follows profile allow-lists / --only"
            }
        }
    }
}

fn status_reason_for(maturity: RuleMaturity) -> &'static str {
    match maturity {
        RuleMaturity::TaintCore => {
            "Graph-based taint/injection family; production CI candidate when taint is enabled"
        }
        RuleMaturity::Structural => {
            "AST/facts with generalized patterns that meet the structural promotion bar"
        }
        RuleMaturity::Heuristic => {
            "Useful smell with higher false-positive risk; review findings before CI hard-fail"
        }
        RuleMaturity::FixtureOnly => {
            "Fixture-corpus evidence only — available under --profile all, not production-certified"
        }
        RuleMaturity::Reserved => {
            "Placeholder / incomplete detector; not for production CI packs until completed"
        }
    }
}

fn documentation_for(maturity: RuleMaturity) -> &'static str {
    match maturity {
        RuleMaturity::TaintCore => "documents/taint.md; documents/go-recommended-pack.md",
        RuleMaturity::Structural => {
            "plans/v0.0.5/cwe-catalog-trust-audit.md §1.3; documents/go-recommended-pack.md"
        }
        RuleMaturity::Heuristic => "documents/go-recommended-pack.md; src/rules/maturity.rs",
        RuleMaturity::FixtureOnly => {
            "documents/go-recommended-pack.md (fixture-only quarantine); plans/v0.0.5/cwe-catalog-trust-audit.md"
        }
        RuleMaturity::Reserved => {
            "documents/go-recommended-pack.md; src/rules/maturity.rs (reserved policy)"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleMaturity;

    /// Representative ids for each maturity class (plan §4.2).
    const REPRESENTATIVES: &[(&str, RuleMaturity)] = &[
        ("CWE-89", RuleMaturity::TaintCore),
        ("CWE-41", RuleMaturity::Structural),
        ("CWE-916", RuleMaturity::Heuristic),
        ("CWE-334", RuleMaturity::FixtureOnly),
        ("BP-63", RuleMaturity::Reserved),
    ];

    #[test]
    fn representatives_cover_all_maturity_classes() {
        for (id, expected) in REPRESENTATIVES {
            assert_eq!(maturity_for(id), *expected, "{id}");
            let exp = RuleExplainability::for_rule(id);
            assert_eq!(exp.maturity, expected.as_str());
            assert_eq!(exp.rule_id, *id);
            assert_eq!(
                exp.quarantined,
                !expected.allowed_in_default_packs(),
                "{id} quarantined flag"
            );
            assert!(!exp.pack_eligibility.is_empty());
            assert!(!exp.status_reason.is_empty());
            assert!(!exp.documentation.is_empty());
        }
    }

    #[test]
    fn fixture_only_documents_all_profile_not_certified() {
        let exp = RuleExplainability::for_rule("CWE-334");
        assert!(exp.quarantined);
        assert!(
            exp.pack_eligibility.contains("--profile all"),
            "{}",
            exp.pack_eligibility
        );
        assert!(
            exp.pack_eligibility.contains("not production-certified")
                || exp.status_reason.contains("not production-certified"),
            "status={}, pack={}",
            exp.status_reason,
            exp.pack_eligibility
        );
        assert!(exp.status_reason.contains("--profile all"));
        assert!(exp.documentation.contains("fixture-only"));
    }

    #[test]
    fn reserved_is_quarantined_advisory() {
        let exp = RuleExplainability::for_rule("BP-63");
        assert!(exp.quarantined);
        assert!(exp.pack_eligibility.contains("advisory"));
        assert_eq!(exp.maturity, "reserved");
    }

    #[test]
    fn taint_core_pack_eligibility_mentions_security() {
        let exp = RuleExplainability::for_rule("CWE-89");
        assert!(!exp.quarantined);
        assert!(exp.pack_eligibility.contains("security"));
        assert!(exp.pack_eligibility.contains("recommended"));
        assert_eq!(exp.maturity, "taint-core");
    }

    #[test]
    fn structural_security_pack_member() {
        let exp = RuleExplainability::for_rule("CWE-41");
        assert!(!exp.quarantined);
        assert!(exp.pack_eligibility.contains("security pack"));
        assert_eq!(exp.maturity, "structural");
    }

    #[test]
    fn heuristic_not_quarantined() {
        let exp = RuleExplainability::for_rule("CWE-916");
        assert!(!exp.quarantined);
        assert_eq!(exp.maturity, "heuristic");
        assert!(
            exp.status_reason.contains("false-positive") || exp.status_reason.contains("smell")
        );
    }

    #[test]
    fn format_block_is_stable_for_representatives() {
        for (id, _) in REPRESENTATIVES {
            let block = RuleExplainability::for_rule(id).format_block();
            assert!(block.starts_with(&format!("Rule ID:           {id}")));
            assert!(block.contains("Maturity:"));
            assert!(block.contains("Pack eligibility:"));
            assert!(block.contains("Status reason:"));
            assert!(block.contains("Documentation:"));
            // Snapshot-friendly: five labeled lines.
            assert_eq!(block.lines().count(), 5, "{id}:\n{block}");
        }
    }

    #[test]
    fn format_block_snapshots_per_maturity() {
        // Inline snapshots keep the surface reviewable without binary I/O.
        insta::assert_snapshot!(
            "explain_taint_core",
            RuleExplainability::for_rule("CWE-89").format_block()
        );
        insta::assert_snapshot!(
            "explain_structural",
            RuleExplainability::for_rule("CWE-41").format_block()
        );
        insta::assert_snapshot!(
            "explain_heuristic",
            RuleExplainability::for_rule("CWE-916").format_block()
        );
        insta::assert_snapshot!(
            "explain_fixture_only",
            RuleExplainability::for_rule("CWE-334").format_block()
        );
        insta::assert_snapshot!(
            "explain_reserved",
            RuleExplainability::for_rule("BP-63").format_block()
        );
    }
}
