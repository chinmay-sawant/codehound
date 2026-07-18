//! Unified run-time configuration: scan context + path filters.

use crate::core::ScanContext;
use crate::engine::path_identity::EXAMPLE_EXCLUDE_GLOBS;

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
    /// When true, exclude example/demo path trees from discovery.
    pub exclude_examples: bool,
}

/// Build [`PathFilters`] from optional TOML config and CLI overrides.
pub fn path_filters_from_config(
    config: Option<&CodehoundConfig>,
    include_tests: bool,
    exclude_examples: bool,
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
    if exclude_examples {
        for glob in EXAMPLE_EXCLUDE_GLOBS {
            if !path_filters.exclude.iter().any(|existing| existing == glob) {
                path_filters.exclude.push((*glob).to_string());
            }
        }
    }
    path_filters
}

/// Build scan context and path filters in one place.
pub fn build_run_config(params: RunConfigParams) -> RunConfig {
    let path_filters = path_filters_from_config(
        params.scan.config.as_ref(),
        params.include_tests,
        params.exclude_examples,
    );
    RunConfig {
        scan_context: build_scan_context(params.scan),
        path_filters,
    }
}
