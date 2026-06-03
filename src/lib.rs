//! SlopGuard — multi-language static analyzer for performance slop.

pub mod ast;
pub mod cli;
pub mod core;
pub mod cwe;
pub mod engine;
pub mod export;
pub mod fixture;
pub mod lang;
pub mod reporting;
pub mod rules;

pub use engine::{AnalysisResult, Analyzer, AnalyzerBuilder};
