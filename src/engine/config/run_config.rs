//! Unified run-time configuration: scan context + path filters.

use crate::core::ScanContext;

use super::scan_context::{ScanContextParams, build_scan_context};
use super::types::{PathFilters, SlopguardConfig};

/// Scan context and path filters built together from CLI + TOML.
#[derive(Debug, Clone)]
pub struct RunConfig {
    pub scan_context: ScanContext,
    pub path_filters: PathFilters,
}

/// Inputs for [`build_run_config`].
#[derive(Debug, Clone, Default)]
pub struct RunConfigParams {
    pub scan: ScanContextParams,
    pub include_tests: bool,
}

/// Build [`PathFilters`] from optional TOML config and CLI overrides.
pub fn path_filters_from_config(
    config: Option<&SlopguardConfig>,
    include_tests: bool,
) -> PathFilters {
    let mut path_filters = config
        .map(|cfg| PathFilters {
            include: cfg.slopguard.include.clone(),
            exclude: cfg.slopguard.exclude.clone(),
            exclude_tests: cfg.slopguard.exclude_tests.unwrap_or(true),
        })
        .unwrap_or_default();
    if include_tests {
        path_filters.exclude_tests = false;
    }
    path_filters
}

/// Build scan context and path filters in one place.
pub fn build_run_config(params: RunConfigParams) -> RunConfig {
    let include_tests = params.include_tests;
    let path_filters = path_filters_from_config(params.scan.config.as_ref(), include_tests);
    RunConfig {
        scan_context: build_scan_context(params.scan),
        path_filters,
    }
}
