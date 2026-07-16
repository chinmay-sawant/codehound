//! Embedder-facing seams: custom registry and cache backend injection.

#![cfg(feature = "go")]

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use codehound::core::{Detector, LanguageId, LanguagePlugin, ParsedUnit, ScanContext};
use codehound::engine::{
    Analyzer, CacheBackend, CacheEntry, CacheError, CacheSession, CacheStore, Registry,
};
use codehound::lang::go::GoPlugin;
use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

#[derive(Debug)]
struct EmptyBackend;

impl CacheBackend for EmptyBackend {
    fn load_entry(&self, _cache_key: &str) -> Option<CacheEntry> {
        None
    }

    fn store_entry(&mut self, _cache_key: &str, _entry: &CacheEntry) -> Result<(), CacheError> {
        Ok(())
    }

    fn delete_entry(&mut self, _cache_key: &str) -> Result<(), CacheError> {
        Ok(())
    }

    fn total_size(&self) -> u64 {
        0
    }

    fn clean_orphans(
        &self,
        _active_keys: &std::collections::HashSet<&str>,
    ) -> Result<usize, CacheError> {
        Ok(0)
    }
}

#[test]
fn analyzer_builder_accepts_custom_registry() {
    let registry = Registry::default();
    let analyzer = Analyzer::builder().registry(registry).build();
    let _analyzer = analyzer;
}

#[test]
fn cache_store_with_backend_accepts_custom_impl() {
    let store = CacheStore::with_backend(Box::new(EmptyBackend));
    assert!(store.manifest().files.is_empty());
}

#[derive(Debug, Clone, Copy)]
enum PanicPoint {
    Run,
    Finalize,
    Reset,
}

#[derive(Debug)]
struct PanickingPlugin {
    panic_point: PanicPoint,
}

impl LanguagePlugin for PanickingPlugin {
    fn id(&self) -> LanguageId {
        GoPlugin.id()
    }

    fn extensions(&self) -> &'static [&'static str] {
        GoPlugin.extensions()
    }

    fn configure_parser(&self, parser: &mut tree_sitter::Parser) -> Result<(), codehound::Error> {
        GoPlugin.configure_parser(parser)
    }

    fn parse_with(
        &self,
        parser: &mut tree_sitter::Parser,
        path: &Path,
        source: std::sync::Arc<str>,
    ) -> Result<ParsedUnit, codehound::Error> {
        GoPlugin.parse_with(parser, path, source)
    }

    fn detectors(&self) -> Vec<Box<dyn Detector>> {
        vec![Box::new(PanickingDetector {
            state: Mutex::new(0),
            panic_in_run: AtomicBool::new(matches!(self.panic_point, PanicPoint::Run)),
            panic_in_finalize: AtomicBool::new(matches!(self.panic_point, PanicPoint::Finalize)),
            panic_in_reset: AtomicBool::new(matches!(self.panic_point, PanicPoint::Reset)),
        })]
    }

    fn loop_node_kinds(&self) -> &'static [&'static str] {
        GoPlugin.loop_node_kinds()
    }

    fn function_node_kinds(&self) -> &'static [&'static str] {
        GoPlugin.function_node_kinds()
    }
}

#[derive(Debug)]
struct PanickingDetector {
    state: Mutex<usize>,
    panic_in_run: AtomicBool,
    panic_in_finalize: AtomicBool,
    panic_in_reset: AtomicBool,
}

impl PanickingDetector {
    const RULES: &'static [&'static str] = &["TEST-FINALIZED", "TEST-FILTERED"];

    fn finding(rule_id: &'static str, message: String) -> Finding {
        Finding::new(FindingInputs::new(
            rule_id,
            "test detector finding",
            "panic.go",
            LineCol::try_new(1, 1).expect("valid test location"),
            message,
            Severity::Info,
            Cow::Borrowed(&[]),
        ))
    }
}

impl Detector for PanickingDetector {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        Self::RULES
    }

    fn run(&self, _ctx: &ScanContext, _unit: &ParsedUnit, _out: &mut Vec<Finding>) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
        if self.panic_in_run.swap(false, Ordering::Relaxed) {
            panic!("test detector run panic");
        }
    }

    fn finalize(&self, _ctx: &ScanContext, out: &mut Vec<Finding>) {
        let count = *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if count == 0 {
            return;
        }
        out.push(Self::finding(
            "TEST-FINALIZED",
            format!("state-count={count}"),
        ));
        out.push(Self::finding(
            "TEST-FILTERED",
            "should be filtered by policy".to_string(),
        ));
        if self.panic_in_finalize.swap(false, Ordering::Relaxed) {
            panic!("test detector finalize panic");
        }
    }

    fn reset_state(&self) {
        if self.panic_in_reset.swap(false, Ordering::Relaxed) {
            panic!("test detector reset panic");
        }
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = 0;
    }
}

fn panic_fixture_path(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "codehound-{label}-{}-{}.go",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    ));
    std::fs::write(&path, "package panicfixture\n\nfunc main() {}\n").expect("write fixture");
    path
}

fn analyzer_with_panic_point(panic_point: PanicPoint, ctx: ScanContext) -> Analyzer {
    Analyzer::builder()
        .registry(
            Registry::with_plugins(vec![Box::new(PanickingPlugin { panic_point })])
                .expect("valid test registry"),
        )
        .scan_context(ctx)
        .build()
}

#[test]
fn detector_state_resets_after_run_panic() {
    let path = panic_fixture_path("run-panic");
    let analyzer = analyzer_with_panic_point(PanicPoint::Run, ScanContext::default());

    let first = analyzer.analyze_paths(&[&path], None).expect("first scan");
    assert_eq!(first.errors.len(), 1);
    assert!(first.findings.is_empty());
    let second = analyzer.analyze_paths(&[&path], None).expect("second scan");
    assert!(
        second
            .findings
            .iter()
            .any(|finding| finding.message == "state-count=1")
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn detector_reset_panic_does_not_abort_scan_cleanup() {
    let path = panic_fixture_path("reset-panic");
    let analyzer = analyzer_with_panic_point(PanicPoint::Reset, ScanContext::default());

    let result = analyzer
        .analyze_paths(&[&path], None)
        .expect("scan should recover");
    assert!(result.errors.is_empty());
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.message == "state-count=1")
    );
    let _ = std::fs::remove_file(path);
}

#[derive(Debug)]
struct CacheStatePlugin;

impl LanguagePlugin for CacheStatePlugin {
    fn id(&self) -> LanguageId {
        GoPlugin.id()
    }

    fn extensions(&self) -> &'static [&'static str] {
        GoPlugin.extensions()
    }

    fn configure_parser(&self, parser: &mut tree_sitter::Parser) -> Result<(), codehound::Error> {
        GoPlugin.configure_parser(parser)
    }

    fn parse_with(
        &self,
        parser: &mut tree_sitter::Parser,
        path: &Path,
        source: std::sync::Arc<str>,
    ) -> Result<ParsedUnit, codehound::Error> {
        GoPlugin.parse_with(parser, path, source)
    }

    fn detectors(&self) -> Vec<Box<dyn Detector>> {
        vec![Box::new(CacheStateDetector {
            state: Mutex::new(0),
        })]
    }

    fn loop_node_kinds(&self) -> &'static [&'static str] {
        GoPlugin.loop_node_kinds()
    }

    fn function_node_kinds(&self) -> &'static [&'static str] {
        GoPlugin.function_node_kinds()
    }
}

#[derive(Debug)]
struct CacheStateDetector {
    state: Mutex<usize>,
}

impl CacheStateDetector {
    const RULES: &'static [&'static str] = &["TEST-CACHE-STATE"];

    fn increment(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
    }
}

impl Detector for CacheStateDetector {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        Self::RULES
    }

    fn run(&self, _ctx: &ScanContext, _unit: &ParsedUnit, _out: &mut Vec<Finding>) {
        self.increment();
    }

    fn accumulate_state(&self, _ctx: &ScanContext, _unit: &ParsedUnit) {
        self.increment();
    }

    fn requires_cache_state(&self, _ctx: &ScanContext) -> bool {
        true
    }

    fn finalize(&self, _ctx: &ScanContext, out: &mut Vec<Finding>) {
        let count = *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        out.push(Self::finding(count));
    }

    fn reset_state(&self) {
        *self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = 0;
    }
}

impl CacheStateDetector {
    fn finding(count: usize) -> Finding {
        Finding::new(FindingInputs::new(
            "TEST-CACHE-STATE",
            "test cache-state detector finding",
            "cache-state.go",
            LineCol::try_new(1, 1).expect("valid test location"),
            format!("state-count={count}"),
            Severity::Info,
            Cow::Borrowed(&[]),
        ))
    }
}

#[test]
fn non_taint_detector_state_is_rebuilt_on_cache_hit() {
    let path = panic_fixture_path("cache-state");
    let analyzer = Analyzer::builder()
        .registry(
            Registry::with_plugins(vec![Box::new(CacheStatePlugin)]).expect("valid test registry"),
        )
        .build();
    let mut cache = CacheStore::in_memory();

    let cold = analyzer
        .analyze_paths(&[&path], Some(CacheSession::open(&mut cache)))
        .expect("cold scan");
    let warm = analyzer
        .analyze_paths(&[&path], Some(CacheSession::open(&mut cache)))
        .expect("warm scan");

    assert_eq!(cold.findings[0].message, "state-count=1");
    assert_eq!(warm.findings[0].message, "state-count=1");
    assert_eq!(warm.stats.as_ref().expect("stats").cache_hits, 1);
    let _ = std::fs::remove_file(path);
}

#[test]
fn detector_state_resets_after_finalize_panic_and_filters_findings() {
    let path = panic_fixture_path("finalize-panic");
    let analyzer = analyzer_with_panic_point(
        PanicPoint::Finalize,
        ScanContext {
            only: Some(["TEST-FINALIZED".to_string()].into_iter().collect()),
            ..ScanContext::default()
        },
    );

    let first = analyzer.analyze_paths(&[&path], None).expect("first scan");
    assert_eq!(first.errors.len(), 1);
    assert_eq!(first.findings.len(), 1);
    assert_eq!(first.findings[0].rule_id, "TEST-FINALIZED");
    assert_eq!(first.findings[0].message, "state-count=1");

    let second = analyzer.analyze_paths(&[&path], None).expect("second scan");
    assert_eq!(second.findings.len(), 1);
    assert_eq!(second.findings[0].message, "state-count=1");
    let _ = std::fs::remove_file(path);
}
