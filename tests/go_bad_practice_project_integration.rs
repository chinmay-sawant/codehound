//! Go bad-practice project-fixture regression tests.

#[path = "helpers/mod.rs"]
mod helpers;

use codehound::engine::Analyzer;
use std::fs;
use std::path::Path;

fn discover_project_cases() -> Vec<String> {
    let root = Path::new("tests/fixtures/go/bad_practices_projects");
    let mut cases = Vec::new();
    for entry in fs::read_dir(root).unwrap_or_else(|e| panic!("read_dir {}: {e}", root.display())) {
        let path = entry.unwrap().path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap()
            .to_string();
        if let Some(case) = name.strip_suffix("-vulnerable") {
            cases.push(case.to_string());
        }
    }
    cases.sort();
    cases
}

/// `BP-47` and `BP-47-fiber` both expect rule `BP-47` (same layout as text BP variants).
fn expected_rule_id(case: &str) -> String {
    let rest = case
        .strip_prefix("BP-")
        .unwrap_or_else(|| panic!("invalid project BP case: {case}"));
    let number = rest
        .split('-')
        .next()
        .unwrap_or_else(|| panic!("invalid project BP case number: {case}"));
    format!("BP-{number}")
}

fn analyzer() -> Analyzer {
    Analyzer::builder().build()
}

#[test]
fn go_bad_practice_project_fixtures_fire_vulnerable_and_silence_safe() {
    let analyzer = analyzer();
    let cases = discover_project_cases();
    let mut failures = Vec::new();

    for case in cases {
        let vulnerable = format!("tests/fixtures/go/bad_practices_projects/{case}-vulnerable");
        let safe = format!("tests/fixtures/go/bad_practices_projects/{case}-safe");
        let expected_rule = expected_rule_id(&case);

        let vulnerable_result = analyzer
            .analyze_paths(&[Path::new(&vulnerable)], None)
            .unwrap_or_else(|e| panic!("analyze {vulnerable}: {e:#}"));
        let vulnerable_ids: Vec<&str> = vulnerable_result
            .findings
            .iter()
            .map(|f| f.rule_id)
            .collect();
        if !vulnerable_ids.contains(&expected_rule.as_str()) {
            failures.push(format!(
                "{vulnerable}: expected {expected_rule}, got {vulnerable_ids:?}"
            ));
        }

        let safe_result = analyzer
            .analyze_paths(&[Path::new(&safe)], None)
            .unwrap_or_else(|e| panic!("analyze {safe}: {e:#}"));
        let safe_ids: Vec<&str> = safe_result.findings.iter().map(|f| f.rule_id).collect();
        if safe_ids.iter().any(|rule_id| rule_id.starts_with("BP-")) {
            failures.push(format!("{safe}: expected no BP findings, got {safe_ids:?}"));
        }
    }

    assert!(
        failures.is_empty(),
        "project BP fixture failures: {failures:#?}"
    );
}

#[test]
fn library_example_server_does_not_trigger_project_server_rules() {
    let root = helpers::unique_temp_root("library-example-server");
    fs::create_dir_all(&root).unwrap_or_else(|e| panic!("create {}: {e}", root.display()));
    fs::write(
        root.join("go.mod"),
        "module example.com/library-with-examples\n\ngo 1.24.0\n",
    )
    .unwrap_or_else(|e| panic!("write go.mod: {e}"));
    for fixture in [
        "tests/fixtures/go/bad_practices_project_text/library.txt",
        "tests/fixtures/go/bad_practices_project_text/example_server.txt",
        "tests/fixtures/go/bad_practices_project_text/comment_only_server.txt",
    ] {
        let text = fs::read_to_string(fixture).unwrap_or_else(|e| panic!("read {fixture}: {e}"));
        let parsed = codehound::fixture::parse_fixture(&text, Path::new(fixture))
            .unwrap_or_else(|e| panic!("parse {fixture}: {e}"));
        let output = root.join(parsed.filename);
        fs::create_dir_all(output.parent().unwrap())
            .unwrap_or_else(|e| panic!("create {}: {e}", output.display()));
        fs::write(&output, parsed.source)
            .unwrap_or_else(|e| panic!("write {}: {e}", output.display()));
    }

    let result = analyzer()
        .analyze_paths(&[&root], None)
        .unwrap_or_else(|e| panic!("analyze {}: {e:#}", root.display()));
    let _ = fs::remove_dir_all(&root);
    let server_rule_findings: Vec<&str> = result
        .findings
        .iter()
        .map(|finding| finding.rule_id)
        .filter(|rule_id| matches!(*rule_id, "BP-47" | "BP-50" | "BP-54" | "BP-55"))
        .collect();

    assert!(
        server_rule_findings.is_empty(),
        "example servers must not make a library a server application: {server_rule_findings:?}"
    );
}

/// Same-`Analyzer` rescan must not reuse BP project facts from a prior scan.
///
/// Starts with a fully-hardened root (safe package doc, go.mod baseline, and
/// server policy), then mutates both `go.mod` and a sibling `.go` file into the
/// vulnerable shape and rescans. If project snapshots were process-lifetime
/// globals, the second scan would still observe the safe facts.
#[test]
fn same_analyzer_rescan_refreshes_bp_project_facts() {
    let root = helpers::unique_temp_root("bp-scan-scoped-rescan");
    fs::create_dir_all(&root).unwrap_or_else(|e| panic!("create {}: {e}", root.display()));

    // Safe go.mod: supported Go version, no unused direct deps.
    fs::write(
        root.join("go.mod"),
        "module example.com/bp-rescan\n\ngo 1.25.0\n",
    )
    .unwrap_or_else(|e| panic!("write go.mod: {e}"));

    // Safe server: package doc, graceful shutdown, signals, rate limit,
    // request-id on logged public route.
    fs::write(
        root.join("main.go"),
        r#"// Package main is a hardened HTTP server used by rescan regression tests.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os/signal"
	"time"

	"golang.org/x/time/rate"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background())
	defer stop()

	limiter := rate.NewLimiter(1, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		if !limiter.Allow() {
			status = http.StatusTooManyRequests
		}
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "generated-request-id"
			r.Header.Set("X-Request-ID", requestID)
		}
		slog.Info("request", "request_id", requestID, "method", r.Method, "path", r.URL.Path)
		w.WriteHeader(status)
	})

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			panic(err)
		}
	}()
	if err := server.ListenAndServe(); err != nil {
		return
	}
}
"#,
    )
    .unwrap_or_else(|e| panic!("write main.go: {e}"));

    let analyzer = analyzer();
    let first = analyzer
        .analyze_paths(&[&root], None)
        .unwrap_or_else(|e| panic!("first scan {}: {e:#}", root.display()));
    let first_ids: Vec<&str> = first.findings.iter().map(|f| f.rule_id).collect();
    for rule in [
        "BP-41", "BP-47", "BP-50", "BP-54", "BP-55", "BP-57", "BP-59",
    ] {
        assert!(
            !first_ids.contains(&rule),
            "first scan should be clean for {rule}, got {first_ids:?}"
        );
    }

    // Mutate go.mod (dependency hygiene) and main.go (package doc + server policy).
    fs::write(
        root.join("go.mod"),
        "module example.com/bp-rescan\n\ngo 1.24.0\n\nrequire github.com/pkg/errors v0.9.1\n",
    )
    .unwrap_or_else(|e| panic!("rewrite go.mod: {e}"));
    fs::write(
        root.join("main.go"),
        r#"package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	if err := http.ListenAndServe(":8080", mux); err != nil {
		return
	}
}
"#,
    )
    .unwrap_or_else(|e| panic!("rewrite main.go: {e}"));

    let second = analyzer
        .analyze_paths(&[&root], None)
        .unwrap_or_else(|e| panic!("second scan {}: {e:#}", root.display()));
    let second_ids: Vec<&str> = second.findings.iter().map(|f| f.rule_id).collect();
    let _ = fs::remove_dir_all(&root);

    for rule in [
        "BP-41", "BP-47", "BP-50", "BP-54", "BP-55", "BP-57", "BP-59",
    ] {
        assert!(
            second_ids.contains(&rule),
            "second scan must refresh project facts and fire {rule}; got {second_ids:?}"
        );
    }
}

/// Concurrent analyzers must not share or evict each other's BP project caches.
///
/// Process-global `OnceLock` maps made one analyzer's `end_scan` clear facts
/// another analyzer was still memoizing. Each `GoBadPracticeScan` now owns its
/// maps, so independent analyzers scanning safe vs vulnerable roots in parallel
/// always observe the correct project facts.
#[test]
fn concurrent_analyzers_do_not_evict_each_others_bp_caches() {
    use std::sync::Arc;
    use std::thread;

    let safe_root = helpers::unique_temp_root("bp-owned-safe");
    let vuln_root = helpers::unique_temp_root("bp-owned-vuln");
    fs::create_dir_all(&safe_root).unwrap_or_else(|e| panic!("create safe: {e}"));
    fs::create_dir_all(&vuln_root).unwrap_or_else(|e| panic!("create vuln: {e}"));

    write_hardened_server(&safe_root);
    write_vulnerable_server(&vuln_root);

    let safe_root = Arc::new(safe_root);
    let vuln_root = Arc::new(vuln_root);
    let project_rules = [
        "BP-41", "BP-47", "BP-50", "BP-54", "BP-55", "BP-57", "BP-59",
    ];

    let mut handles = Vec::new();
    for i in 0..8 {
        let safe = Arc::clone(&safe_root);
        let vuln = Arc::clone(&vuln_root);
        handles.push(thread::spawn(move || {
            // Fresh analyzer (and therefore BP detector + cache maps) per thread.
            let analyzer = Analyzer::builder().build();
            for round in 0..12 {
                let use_safe = (i + round) % 2 == 0;
                let root = if use_safe {
                    safe.as_path()
                } else {
                    vuln.as_path()
                };
                let result = analyzer
                    .analyze_paths(&[root], None)
                    .unwrap_or_else(|e| panic!("scan {}: {e:#}", root.display()));
                let ids: Vec<&str> = result.findings.iter().map(|f| f.rule_id).collect();
                if use_safe {
                    for rule in project_rules {
                        assert!(
                            !ids.contains(&rule),
                            "safe root must stay clean for {rule} under concurrency; got {ids:?}"
                        );
                    }
                } else {
                    for rule in project_rules {
                        assert!(
                            ids.contains(&rule),
                            "vulnerable root must fire {rule} under concurrency; got {ids:?}"
                        );
                    }
                }
            }
        }));
    }

    for handle in handles {
        handle
            .join()
            .expect("concurrent BP analyzer thread panicked");
    }

    let _ = fs::remove_dir_all(safe_root.as_ref());
    let _ = fs::remove_dir_all(vuln_root.as_ref());
}

fn write_hardened_server(root: &Path) {
    fs::write(
        root.join("go.mod"),
        "module example.com/bp-owned-safe\n\ngo 1.25.0\n",
    )
    .unwrap_or_else(|e| panic!("write go.mod: {e}"));
    fs::write(
        root.join("main.go"),
        r#"// Package main is a hardened HTTP server used by concurrent ownership tests.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os/signal"
	"time"

	"golang.org/x/time/rate"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background())
	defer stop()

	limiter := rate.NewLimiter(1, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		status := http.StatusOK
		if !limiter.Allow() {
			status = http.StatusTooManyRequests
		}
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = "generated-request-id"
			r.Header.Set("X-Request-ID", requestID)
		}
		slog.Info("request", "request_id", requestID, "method", r.Method, "path", r.URL.Path)
		w.WriteHeader(status)
	})

	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		if err := server.Shutdown(context.Background()); err != nil {
			panic(err)
		}
	}()
	if err := server.ListenAndServe(); err != nil {
		return
	}
}
"#,
    )
    .unwrap_or_else(|e| panic!("write main.go: {e}"));
}

fn write_vulnerable_server(root: &Path) {
    fs::write(
        root.join("go.mod"),
        "module example.com/bp-owned-vuln\n\ngo 1.24.0\n\nrequire github.com/pkg/errors v0.9.1\n",
    )
    .unwrap_or_else(|e| panic!("write go.mod: {e}"));
    fs::write(
        root.join("main.go"),
        r#"package main

import (
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("request %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	if err := http.ListenAndServe(":8080", mux); err != nil {
		return
	}
}
"#,
    )
    .unwrap_or_else(|e| panic!("write main.go: {e}"));
}
