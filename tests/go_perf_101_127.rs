//! Direct unit tests for the PERF-101..PERF-127 Category-A detectors.
//!
//! Each detector is exercised through the full Analyzer path so the
//! test verifies end-to-end registration + dispatch. The tests do
//! NOT depend on the `tests/fixtures/go/perf/` directory (the
//! contiguity test there requires PERF-1..PERF-100 to be unbroken, so
//! adding isolated fixtures for 103/115/116/117/120/124 would clash
//! with that). Instead, the detectors are validated through the
//! registry on small in-memory Go sources.

use slopguard::core::LanguagePlugin;
use slopguard::core::ScanContext;
use slopguard::engine::Analyzer;
use slopguard::lang::go::GoPlugin;
use std::path::PathBuf;
use std::sync::Arc;

fn run_on_source(source: &str) -> Vec<String> {
    let plugin = GoPlugin;
    let mut parser = tree_sitter::Parser::new();
    plugin.configure_parser(&mut parser);
    let unit = plugin
        .parse_with(&mut parser, &PathBuf::from("test.go"), Arc::from(source))
        .expect("parse");
    // We don't need to run detectors directly — the analyzer
    // pipeline does the full dispatch. To exercise it on a single
    // unit, we call the higher-level `Analyzer::analyze_units` API
    // which exists for tests.
    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let findings = analyzer.analyze_units(&[unit]);
    let mut ids: Vec<String> = findings.iter().map(|f| f.rule_id.to_string()).collect();
    ids.sort();
    ids.dedup();
    ids
}

#[test]
fn perf_103_detects_unclosed_body() {
    let src = r#"
package x
import "net/http"
func Fetch() {
    resp, _ := http.Get("http://x")
    _ = resp
}
"#;
    let ids = run_on_source(src);
    assert!(ids.contains(&"PERF-103".to_string()), "got {ids:?}");

    let safe = r#"
package x
import "net/http"
func Fetch() {
    resp, _ := http.Get("http://x")
    defer resp.Body.Close()
    _ = resp
}
"#;
    let ids = run_on_source(safe);
    assert!(!ids.contains(&"PERF-103".to_string()), "got {ids:?}");
}

#[test]
fn perf_115_detects_strings_compare_to_zero() {
    let src = r#"
package x
import "strings"
func Eq(a, b string) bool { return strings.Compare(a, b) == 0 }
"#;
    let ids = run_on_source(src);
    assert!(ids.contains(&"PERF-115".to_string()), "got {ids:?}");

    let safe = r#"
package x
func Eq(a, b string) bool { return a == b }
"#;
    let ids = run_on_source(safe);
    assert!(!ids.contains(&"PERF-115".to_string()), "got {ids:?}");
}

#[test]
fn perf_116_detects_strings_index_to_neg_one() {
    let src = r#"
package x
import "strings"
func Has(s, sub string) bool { return strings.Index(s, sub) != -1 }
"#;
    let ids = run_on_source(src);
    assert!(ids.contains(&"PERF-116".to_string()), "got {ids:?}");

    let safe = r#"
package x
import "strings"
func Has(s, sub string) bool { return strings.Contains(s, sub) }
"#;
    let ids = run_on_source(safe);
    assert!(!ids.contains(&"PERF-116".to_string()), "got {ids:?}");
}

#[test]
fn perf_117_detects_bytes_compare_to_zero() {
    let src = r#"
package x
import "bytes"
func Eq(a, b []byte) bool { return bytes.Compare(a, b) == 0 }
"#;
    let ids = run_on_source(src);
    assert!(ids.contains(&"PERF-117".to_string()), "got {ids:?}");

    let safe = r#"
package x
import "bytes"
func Eq(a, b []byte) bool { return bytes.Equal(a, b) }
"#;
    let ids = run_on_source(safe);
    assert!(!ids.contains(&"PERF-117".to_string()), "got {ids:?}");
}

#[test]
fn perf_120_detects_time_now_sub() {
    let src = r#"
package x
import "time"
func Elapsed(t time.Time) time.Duration { return time.Now().Sub(t) }
"#;
    let ids = run_on_source(src);
    assert!(ids.contains(&"PERF-120".to_string()), "got {ids:?}");

    let safe = r#"
package x
import "time"
func Elapsed(t time.Time) time.Duration { return time.Since(t) }
"#;
    let ids = run_on_source(safe);
    assert!(!ids.contains(&"PERF-120".to_string()), "got {ids:?}");
}

#[test]
fn perf_124_detects_strings_replace_with_neg_one() {
    let src = r#"
package x
import "strings"
func R(s, old, new string) string { return strings.Replace(s, old, new, -1) }
"#;
    let ids = run_on_source(src);
    assert!(ids.contains(&"PERF-124".to_string()), "got {ids:?}");

    let safe = r#"
package x
import "strings"
func R(s, old, new string) string { return strings.ReplaceAll(s, old, new) }
"#;
    let ids = run_on_source(safe);
    assert!(!ids.contains(&"PERF-124".to_string()), "got {ids:?}");
}
