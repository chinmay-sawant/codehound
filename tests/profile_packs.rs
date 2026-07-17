//! Profile packs: size, membership, and quarantine guarantees.

use codehound::core::{ScanContext, ScanProfile};
use codehound::engine::{ScanContextParams, build_scan_context};
use codehound::rules::{RuleMaturity, is_quarantined_from_default_packs, maturity_for};

#[test]
fn recommended_pack_is_small_and_bp_free() {
    let mut only = None;
    let mut fail = codehound::core::FailPolicy::MediumAsErrors;
    let mut taint = false;
    let mut bp = true;
    ScanProfile::Recommended.apply_base(codehound::core::ProfileApplyTarget {
        only: &mut only,
        fail_policy: &mut fail,
        cli_set_fail_policy: false,
        taint_enabled: &mut taint,
        bad_practices_enabled: &mut bp,
        cli_set_taint: false,
        cli_set_bp: false,
    });
    let only = only.expect("recommended has only filter");
    assert!(
        only.len() <= 30,
        "recommended pack too large: {}",
        only.len()
    );
    assert!(!bp, "recommended must disable BP");
    assert!(!taint, "recommended keeps taint off by default");
    assert_eq!(fail, codehound::core::FailPolicy::Strict);
    assert!(only.iter().any(|r| r == "PERF-101"));
    assert!(only.iter().any(|r| r == "CWE-22"));
    assert!(!only.iter().any(|r| r.starts_with("BP-")));
}

#[test]
fn security_enables_taint_and_skips_fixture_only() {
    let ctx = build_scan_context(ScanContextParams {
        profile: ScanProfile::Security,
        ..Default::default()
    });
    assert!(ctx.taint_enabled);
    assert!(!ctx.bad_practices_enabled);
    assert!(
        !ctx.allows("CWE-334"),
        "fixture-only must not run in security"
    );
    assert!(ctx.allows("CWE-22"));
    assert!(!ctx.allows("PERF-101"), "security pack is CWE-focused");
}

#[test]
fn recommended_does_not_allow_fixture_only_ids() {
    let ctx = build_scan_context(ScanContextParams {
        profile: ScanProfile::Recommended,
        ..Default::default()
    });
    for id in [
        "CWE-334", "CWE-335", "CWE-338", "CWE-342", "CWE-343", "CWE-798",
    ] {
        assert!(
            is_quarantined_from_default_packs(id),
            "{id} should be fixture-only"
        );
        assert!(!ctx.allows(id), "{id} must not be allowed in recommended");
    }
}

#[test]
fn all_profile_keeps_full_catalog_behavior() {
    let ctx = build_scan_context(ScanContextParams {
        profile: ScanProfile::All,
        ..Default::default()
    });
    assert!(ctx.only.is_none());
    assert!(ctx.bad_practices_enabled);
    assert!(ctx.allows("CWE-334"));
    assert!(ctx.allows("BP-1"));
    assert!(ctx.allows("PERF-213"));
}

#[test]
fn maturity_tags_cover_taint_core() {
    assert_eq!(maturity_for("CWE-89"), RuleMaturity::TaintCore);
    assert_eq!(maturity_for("CWE-334"), RuleMaturity::FixtureOnly);
}

#[test]
fn style_is_bp_only_advisory() {
    let ctx = build_scan_context(ScanContextParams {
        profile: ScanProfile::Style,
        ..Default::default()
    });
    assert!(ctx.bad_practices_enabled);
    assert!(ctx.allows("BP-1"));
    assert!(!ctx.allows("PERF-101"));
    assert_eq!(ctx.fail_policy, codehound::core::FailPolicy::NoFail);
    // Opinion rules off by default in style.
    assert!(!ctx.allows("BP-21"));
    assert!(!ctx.allows("BP-28"));
}

#[test]
fn style_can_opt_into_opinion_rules_via_only() {
    let ctx = build_scan_context(ScanContextParams {
        profile: ScanProfile::Style,
        only: vec!["BP-28".to_string()],
        ..Default::default()
    });
    assert!(ctx.allows("BP-28"));
    assert!(!ctx.allows("BP-21"), "unrequested opinion rule stays off");
}

#[test]
fn bp_63_reserved_quarantined_from_recommended() {
    assert_eq!(maturity_for("BP-63"), RuleMaturity::Reserved);
    assert!(is_quarantined_from_default_packs("BP-63"));
    let ctx = build_scan_context(ScanContextParams {
        profile: ScanProfile::Recommended,
        ..Default::default()
    });
    assert!(!ctx.allows("BP-63"));
}

#[test]
fn scan_context_default_library_is_unfiltered() {
    // Library embedders keep full catalog; CLI applies recommended via ScanContextParams.
    let ctx = ScanContext::default();
    assert!(ctx.only.is_none());
    assert!(ctx.allows("BP-1"));
    assert!(
        !ctx.retain_sources,
        "default CI path must not retain source_cache"
    );
}

#[test]
fn retain_sources_opt_in_via_params() {
    let ctx = build_scan_context(ScanContextParams {
        retain_sources: true,
        ..Default::default()
    });
    assert!(ctx.retain_sources);
}
