//! Build `ScanContext` from CLI flags + optional config file.

use crate::core::{FailPolicy, ScanContext};

use super::types::SlopguardConfig;

/// Build scan context from CLI + optional config file.
pub fn build_scan_context(
    only: Vec<String>,
    skip: Vec<String>,
    fail_policy: FailPolicy,
    config: Option<SlopguardConfig>,
    cli_set_fail_policy: bool,
    debug_timing: bool,
    diagnostics: bool,
) -> ScanContext {
    let mut ctx = ScanContext {
        only: if only.is_empty() {
            None
        } else {
            Some(only.into_iter().collect())
        },
        skip: skip.into_iter().collect(),
        fail_policy,
        show_ignored: false,
        debug_timing,
        diagnostics,
        taint_enabled: false,
        taint_show_paths: false,
        bad_practices_enabled: true,
        bad_practice_severity: None,
    };
    if let Some(cfg) = config {
        ctx = cfg.merge_into(ctx, cli_set_fail_policy);
    }
    ctx
}
