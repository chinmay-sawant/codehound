//! Build `ScanContext` from CLI flags + optional config file.

use crate::core::{FailPolicy, ScanContext};

use super::types::SlopguardConfig;

/// Parameters for [`build_scan_context`].
#[derive(Default)]
pub struct ScanContextParams {
    pub only: Vec<String>,
    pub skip: Vec<String>,
    pub fail_policy: FailPolicy,
    pub config: Option<SlopguardConfig>,
    pub cli_set_fail_policy: bool,
    pub debug_timing: bool,
    pub diagnostics: bool,
    pub diagnostics_summary: bool,
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
        taint_enabled: true,
        taint_show_paths: false,
        bad_practices_enabled: true,
        bad_practice_severity: None,
    };
    if let Some(cfg) = params.config {
        ctx = cfg.merge_into(ctx, params.cli_set_fail_policy);
    }
    ctx
}
