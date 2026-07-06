#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

//! # CodeHound
//!
//! CodeHound is a multi-language static analyzer for performance bottlenecks
//! and security weaknesses ("slop"). It currently ships with:
//!
//! - **Go** — 175 CWE heuristic detectors
//! - **Python** — 1 performance rule (`SLOP101`: `re.compile` inside a loop)
//!
//! ## Quick start (as a library)
//!
//! ```no_run
//! use codehound::engine::{Analyzer, CodehoundConfig, resolve_language_filter, Registry};
//! use codehound::core::ScanContext;
//!
//! let registry = Registry::default();
//! let config = CodehoundConfig::default();
//! let filter = resolve_language_filter(None, Some(&config), &registry).unwrap();
//!
//! let analyzer = Analyzer::builder()
//!     .scan_context(ScanContext::default())
//!     .language_filter(filter)
//!     .build();
//!
//! let result = analyzer.analyze_paths(&["."], None).unwrap();
//! println!("{} findings", result.findings.len());
//! ```
//!
//! ## Feature flags
//!
//! - `go` (default) — Go tree-sitter grammar and the CWE bundle
//! - `python` (default) — Python tree-sitter grammar and the `SLOP101` rule
//! - `cli` (default) — clap-derived CLI types (`codehound::cli`)
//! - `typescript` (optional) — reserves `LanguageId::TypeScript` (no plugin yet)
//! - `default` — `go`, `python`, `terminal-output`, and `cli`
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
//! - [`ast`] — tree-sitter helpers (`line_col_with_starts`, `walk_nodes`, ...)
//! - [`cli`] — clap-derived argument definitions (binary only)
//!
//! See `docs/architecture-performance.md` for the pipeline diagram and
//! `docs/configuration.md` for `codehound.toml` schema.
//!
//! ## Documentation ratchet (v2.0.0)
//!
//! Crate-wide `#![warn(missing_docs)]` is deferred until the public API surface
//! is documented module-by-module. Planned order: `rules` → `core` → `engine` →
//! `lang`, then enable `#![deny(missing_docs)]` on each module as coverage lands.

pub mod ast;
#[cfg(feature = "cli")]
pub mod cli;
pub mod core;
pub mod cwe;
pub mod engine;
pub mod error;
pub mod export;
pub mod fixture;
pub mod lang;
pub mod reporting;
pub mod rules;

pub use engine::{AnalysisResult, Analyzer, AnalyzerBuilder};
pub use error::Error;
