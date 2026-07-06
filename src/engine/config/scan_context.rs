//! Build `ScanContext` from CLI flags + optional config file.

use crate::core::{FailPolicy, ScanContext};

use super::types::CodehoundConfig;

/// Parameters for [`build_scan_context`].
#[derive(Debug, Clone, Default)]
pub struct ScanContextParams {
    pub only: Vec<String>,
    pub skip: Vec<String>,
    pub fail_policy: FailPolicy,
    pub config: Option<CodehoundConfig>,
    pub cli_set_fail_policy: bool,
    pub debug_timing: bool,
    pub diagnostics: bool,
    pub diagnostics_summary: bool,
    pub verbose: bool,
    pub bp_only: bool,
    pub no_bp: bool,
    pub taint: bool,
    pub no_taint: bool,
    pub taint_show_paths: bool,
    pub show_ignored: bool,
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
        taint_enabled: true,
        taint_show_paths: false,
        bad_practices_enabled: true,
        bad_practice_severity: None,
    };
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
    if params.show_ignored {
        ctx.show_ignored = true;
    }
    ctx
}
