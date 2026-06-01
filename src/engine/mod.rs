//! Analysis engine — orchestration only.

mod analyzer;
mod config;
mod parse_pool;
mod registry;
mod result;
mod walk;

pub use analyzer::{Analyzer, AnalyzerBuilder};
pub use config::{SlopguardConfig, build_scan_context};
pub use registry::Registry;
pub use result::AnalysisResult;
