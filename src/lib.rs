#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

//! # CodeHound
//!
//! Multi-language static analyzer focused on **Go performance hot paths**,
//! framework footguns, and curated CWE heuristics. Complements golangci-lint /
//! staticcheck / govulncheck — does not replace them.
//!
//! - **Go** — PERF, CWE (structural + optional taint), bad-practice (style pack)
//! - **Python** — `SLOP101` (`re.compile` in a loop); historical id, kept stable
//!
//! ## Quick start (library)
//!
//! ```no_run
//! use codehound::core::{ScanContext, ScanProfile};
//! use codehound::engine::{Analyzer, CodehoundConfig, resolve_language_filter, Registry};
//! use codehound::engine::{ScanContextParams, build_scan_context};
//!
//! // Match CLI recommended pack defaults for embedders who want CI-like gates.
//! let ctx = build_scan_context(ScanContextParams {
//!     profile: ScanProfile::Recommended,
//!     ..Default::default()
//! });
//!
//! let registry = Registry::default();
//! let config = CodehoundConfig::default();
//! let filter = resolve_language_filter(None, Some(&config), &registry).unwrap();
//!
//! let analyzer = Analyzer::builder()
//!     .scan_context(ctx)
//!     .language_filter(filter)
//!     .build();
//!
//! let result = analyzer.analyze_paths(&["."], None).unwrap();
//! for f in &result.findings {
//!     // PERF-*, CWE-*, BP-* share the same Finding wire shape.
//!     println!("{} {}:{} {}", f.rule_id, f.file, f.line, f.message);
//! }
//! ```
//!
//! ## Feature flags
//!
//! | Feature | Default | Role |
//! |---------|---------|------|
//! | `go` | yes | Go tree-sitter + CWE/PERF/BP |
//! | `python` | yes | Python grammar + `SLOP101` |
//! | `cli` | yes | clap CLI types |
//! | `terminal-output` | yes | colored text reporter |
//! | `typescript` | no | LanguageId stub only |
//!
//! Minimal: `cargo build --no-default-features --features go,cli`.
//!
//! ## Semver (Finding wire)
//!
//! - **Stable enough for 0.1.x:** `rule_id`, `file`, `line`, `column`, `message`,
//!   `severity`, optional `evidence` / `snippet`.
//! - **May change in 0.x:** fingerprint format (regenerate baselines), optional
//!   fields, SARIF property bags.
//! - Prefer reading published fields; ignore unknown JSON keys.
//!
//! ## Architecture
//!
//! - [`engine`] — orchestration: scan, registry, parallel parse, cache, baseline
//! - [`core`] — `LanguagePlugin`, `Detector`, `ParsedUnit`, `ScanContext`, profiles
//! - [`lang`] — language plugins (Go, Python)
//! - [`rules`] — finding + metadata + severity + maturity
//! - [`reporting`] — text, JSON, SARIF
//! - [`export`] — optional context/chunk files (off by default)
//!
//! See `docs/architecture-performance.md`, `ROADMAP.md`, and `CONTRIBUTING.md`.

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
pub use error::{Error, IoOp};
