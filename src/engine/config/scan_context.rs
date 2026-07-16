//! Build `ScanContext` from CLI flags + optional config file.

use crate::core::{FailPolicy, ProfileApplyTarget, ScanContext, ScanProfile};
use crate::rules::is_quarantined_from_default_packs;

use super::types::CodehoundConfig;

/// Parameters for [`build_scan_context`].
#[derive(Debug, Clone, Default)]
pub struct ScanContextParams {
    /// Rule IDs / globs to run exclusively when non-empty.
    pub only: Vec<String>,
    /// Rule IDs / globs to skip.
    pub skip: Vec<String>,
    /// Process exit policy for findings.
    pub fail_policy: FailPolicy,
    /// Optional loaded `codehound.toml` document.
    pub config: Option<CodehoundConfig>,
    /// True when the CLI explicitly set the fail policy (blocks config override).
    pub cli_set_fail_policy: bool,
    /// Enable per-detector timing collection and reporting.
    pub debug_timing: bool,
    /// Emit machine-readable diagnostics after the scan.
    pub diagnostics: bool,
    /// Print a compact scan summary to the terminal.
    pub diagnostics_summary: bool,
    /// Verbose text output (extra stats / phase timing).
    pub verbose: bool,
    /// Restrict the run to bad-practice (`BP-*`) rules only.
    pub bp_only: bool,
    /// Disable the bad-practice pack entirely.
    pub no_bp: bool,
    /// Enable experimental taint tracking.
    pub taint: bool,
    /// Explicitly disable taint tracking.
    pub no_taint: bool,
    /// Attach taint-path evidence when taint is enabled.
    pub taint_show_paths: bool,
    /// Inter-procedural hops (clamped 1..=4 when applied).
    pub taint_depth: u32,
    /// Keep findings suppressed by inline/file ignores in results.
    pub show_ignored: bool,
    /// Product pack. Default [`ScanProfile::Recommended`] for CLI; library callers may use `All`.
    pub profile: ScanProfile,
    /// Retain file sources for export/context (default off).
    pub retain_sources: bool,
}

/// Build scan context from CLI + optional config file.
pub fn build_scan_context(params: ScanContextParams) -> ScanContext {
    let mut ctx = ScanContext {
        only: if params.only.is_empty() {
            None
        } else {
            Some(params.only.into_iter().collect())
        },
        skip: params.skip.into_iter().collect(),
        fail_policy: params.fail_policy,
        show_ignored: false,
        debug_timing: params.debug_timing,
        diagnostics: params.diagnostics,
        diagnostics_summary: params.diagnostics_summary,
        verbose: params.verbose,
        taint_enabled: false,
        taint_show_paths: false,
        taint_max_depth: 1,
        bad_practices_enabled: true,
        bad_practice_severity: None,
        severity_overrides: Default::default(),
        retain_sources: params.retain_sources,
    };

    let cli_set_taint = params.taint || params.no_taint;
    let cli_set_bp = params.bp_only || params.no_bp;

    // Apply product pack before config merge so config skip/only can still refine.
    params.profile.apply_base(ProfileApplyTarget {
        only: &mut ctx.only,
        fail_policy: &mut ctx.fail_policy,
        cli_set_fail_policy: params.cli_set_fail_policy,
        taint_enabled: &mut ctx.taint_enabled,
        bad_practices_enabled: &mut ctx.bad_practices_enabled,
        cli_set_taint,
        cli_set_bp,
    });

    if let Some(cfg) = params.config {
        ctx = cfg.merge_into(ctx, params.cli_set_fail_policy);
    }
    if params.bp_only {
        ctx.only = Some(["BP-*".to_string()].into_iter().collect());
        ctx.bad_practices_enabled = true;
    }
    if params.no_bp {
        ctx.bad_practices_enabled = false;
    }
    if params.taint {
        ctx.taint_enabled = true;
    }
    if params.no_taint {
        ctx.taint_enabled = false;
    }
    if params.taint_show_paths {
        ctx.taint_show_paths = true;
    }
    if params.taint_depth > 0 {
        ctx.taint_max_depth = params.taint_depth.clamp(1, 4);
    }
    if params.show_ignored {
        ctx.show_ignored = true;
    }

    // Quarantine fixture-only / reserved from recommended & security packs.
    if matches!(
        params.profile,
        ScanProfile::Recommended | ScanProfile::Security | ScanProfile::Perf
    ) {
        if let Some(only) = ctx.only.as_mut() {
            only.retain(|r| r.ends_with('*') || !is_quarantined_from_default_packs(r));
        }
        // Also skip known quarantined IDs if someone merges them via --only.
        for id in [
            "CWE-334", "CWE-335", "CWE-338", "CWE-342", "CWE-343", "BP-63",
        ] {
            if is_quarantined_from_default_packs(id) {
                ctx.skip.insert(id.to_string());
            }
        }
    }

    // Style pack: keep BP advisory (info/low) via fail policy already NoFail.
    if params.profile == ScanProfile::Style && !params.cli_set_fail_policy {
        ctx.fail_policy = FailPolicy::NoFail;
    }

    // Opinion / low-value BP rules: off by default in style unless the user
    // explicitly requested them via --only (exact id).
    for id in params.profile.style_default_skip() {
        let explicitly_requested = ctx
            .only
            .as_ref()
            .is_some_and(|only| only.iter().any(|p| p == id));
        if !explicitly_requested {
            ctx.skip.insert((*id).to_string());
        }
    }

    ctx
}
