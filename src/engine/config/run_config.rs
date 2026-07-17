//! Unified run-time configuration: scan context + path filters.

use crate::core::ScanContext;

use super::scan_context::{ScanContextParams, build_scan_context};
use super::types::{CodehoundConfig, PathFilters};

/// Scan context and path filters built together from CLI + TOML.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// Detector filters, profile flags, and fail policy for this run.
    pub scan_context: ScanContext,
    /// Path include/exclude filters applied during discovery.
    pub path_filters: PathFilters,
}

/// Inputs for [`build_run_config`].
#[derive(Debug, Clone, Default)]
pub struct RunConfigParams {
    /// Parameters used to build [`ScanContext`].
    pub scan: ScanContextParams,
    /// When true, do not exclude test files from discovery.
    pub include_tests: bool,
}

/// Build [`PathFilters`] from optional TOML config and CLI overrides.
pub fn path_filters_from_config(
    config: Option<&CodehoundConfig>,
    include_tests: bool,
) -> PathFilters {
    let mut path_filters = config
        .map(|cfg| PathFilters {
            include: cfg.codehound.include.clone(),
            exclude: cfg.codehound.exclude.clone(),
            exclude_tests: cfg.codehound.exclude_tests.unwrap_or(true),
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
