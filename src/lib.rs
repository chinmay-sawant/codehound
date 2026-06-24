//! # SlopGuard
//!
//! SlopGuard is a multi-language static analyzer for performance bottlenecks
//! and security weaknesses ("slop"). It currently ships with:
//!
//! - **Go** — 175 CWE heuristic detectors
//! - **Python** — 1 performance rule (`SLOP101`: `re.compile` inside a loop)
//!
//! ## Quick start (as a library)
//!
//! ```no_run
//! use slopguard::engine::{Analyzer, SlopguardConfig, resolve_language_filter, Registry};
//! use slopguard::core::ScanContext;
//!
//! let registry = Registry::default();
//! let config = SlopguardConfig::default();
//! let filter = resolve_language_filter(None, Some(&config), &registry).unwrap();
//!
//! let analyzer = Analyzer::builder()
//!     .scan_context(ScanContext::default())
//!     .language_filter(filter)
//!     .build();
//!
//! let result = analyzer.analyze_paths(["."], None).unwrap();
//! println!("{} findings", result.findings.len());
//! ```
//!
//! ## Feature flags
//!
//! - `go` (default) — Go tree-sitter grammar and the CWE bundle
//! - `python` (default) — Python tree-sitter grammar and the `SLOP101` rule
//! - `default` — both `go` and `python`
//!
//! Minimal build: `cargo build --no-default-features --features go`.
//!
//! ## Architecture
//!
//! - [`engine`] — orchestration: scan, registry, parallel parse, analysis
//! - [`core`] — traits: `LanguagePlugin`, `Detector`, `ParsedUnit`,
//!   `ScanContext`, `FailPolicy`
//! - [`lang`] — language plugins (Go, Python)
//! - [`rules`] — finding + metadata + severity
//! - [`cwe`] — curated CWE reference catalog
//! - [`reporting`] — text, JSON, SARIF output
//! - [`export`] — per-finding context files and chunk files
//! - [`fixture`] — `.txt` test fixture materialization
//! - [`ast`] — tree-sitter helpers (`line_col`, `walk_nodes`, ...)
//! - [`cli`] — clap-derived argument definitions (binary only)
//!
//! See `docs/architecture-performance.md` for the pipeline diagram and
//! `docs/configuration.md` for `slopguard.toml` schema.

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
