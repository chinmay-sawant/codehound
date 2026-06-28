#![cfg(feature = "go")]

#[path = "helpers/mod.rs"]
mod helpers;
use helpers::cache::dep_helpers;
use helpers::unique_temp_root;

use slopguard::core::ScanContext;
use slopguard::engine::{Analyzer, CacheStore, DEFAULT_CACHE_DIR, go_module_prefix};

// ---- Dependency extraction + transitive invalidation -------------------

#[test]
fn go_dependency_extraction_finds_local_package() {
    use dep_helpers::*;
    let root = unique_temp_root("local-pkg");
    std::fs::create_dir_all(root.join("pkg/db")).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(&root.join("pkg/db/db.go"), "package db\n\nfunc Open() {}\n");
    write_file(
        &root.join("pkg/handler/handler.go"),
        r#"package handler

import "example.com/proj/pkg/db"

func Run() { db.Open() }
"#,
    );
    let deps = deps_for(&root, "pkg/handler/handler.go");
    assert!(
        deps.iter().any(|d| d.ends_with("pkg/db/db.go")),
        "expected handler to depend on db.go, got {deps:?}"
    );
}

#[test]
fn go_dependency_extraction_skips_stdlib_and_third_party() {
    use dep_helpers::*;
    let root = unique_temp_root("skip-stdlib");
    std::fs::create_dir_all(root.join("pkg")).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(
        &root.join("pkg/x.go"),
        r#"package x

import (
    "fmt"
    "net/http"
    "github.com/gin-gonic/gin"
)
"#,
    );
    let deps = deps_for(&root, "pkg/x.go");
    assert!(deps.is_empty(), "expected no local deps, got {deps:?}");
}

#[test]
fn go_dependency_extraction_handles_directory_import() {
    use dep_helpers::*;
    let root = unique_temp_root("dir-import");
    std::fs::create_dir_all(root.join("pkg/handlers")).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(&root.join("pkg/handlers/a.go"), "package handlers\n");
    write_file(&root.join("pkg/handlers/b.go"), "package handlers\n");
    write_file(
        &root.join("main.go"),
        r#"package main

import "example.com/proj/pkg/handlers"
"#,
    );
    let deps = deps_for(&root, "main.go");
    assert_eq!(
        deps.len(),
        2,
        "expected 2 files in pkg/handlers, got {deps:?}"
    );
    assert!(deps.iter().any(|d| d.ends_with("pkg/handlers/a.go")));
    assert!(deps.iter().any(|d| d.ends_with("pkg/handlers/b.go")));
}

#[test]
fn go_module_prefix_returns_none_for_missing_go_mod() {
    let root = unique_temp_root("no-go-mod");
    std::fs::create_dir_all(&root).unwrap();
    assert!(go_module_prefix(&root).is_none());
}

#[test]
fn transitive_invalidation_clears_dependents() {
    use dep_helpers::*;
    use slopguard::engine::discover_cache_dir;

    let root = unique_temp_root("transitive");
    std::fs::create_dir_all(root.join("pkg/db")).unwrap();
    std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
    write_file(
        &root.join("pkg/db/db.go"),
        r#"package db

import "os/exec"

func Run() { exec.Command("sh", "-c", "ls").Run() }
"#,
    );
    write_file(
        &root.join("pkg/handler.go"),
        r#"package handler

import "example.com/proj/pkg/db"

func Handle() { db.Run() }
"#,
    );

    // First scan: both files end up in the manifest, and handler.go
    // declares db.go as a dependency.
    let cache_dir = root.join(DEFAULT_CACHE_DIR);
    let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 500).unwrap();
    {
        let analyzer = Analyzer::builder()
            .with_default_filter()
            .scan_context(ScanContext::default())
            .build();
        let _ = analyzer.analyze_paths(&[&root], Some(&mut cache)).unwrap();
    }
    cache.flush().unwrap();

    let manifest = cache.manifest();
    let handler_entry = manifest
        .files
        .iter()
        .find(|(k, _)| k.ends_with("pkg/handler.go"))
        .map(|(_, v)| v.clone())
        .expect("handler.go in manifest after first scan");
    assert!(
        handler_entry
            .dependencies
            .iter()
            .any(|d| d.ends_with("db.go")),
        "handler.go should depend on db.go, deps were {:?}",
        handler_entry.dependencies
    );

    // Edit db.go: its content hash will change on the next scan,
    // which means handler.go's cache entry must be invalidated via
    // the transitive invalidation hook.
    let mut db_src = std::fs::read_to_string(root.join("pkg/db/db.go")).unwrap();
    db_src.push_str("\n// touch\n");
    std::fs::write(root.join("pkg/db/db.go"), &db_src).unwrap();

    let mut cache2 = CacheStore::open_with_capacity(cache_dir, 500).unwrap();
    {
        let analyzer = Analyzer::builder()
            .with_default_filter()
            .scan_context(ScanContext::default())
            .build();
        let _ = analyzer.analyze_paths(&[&root], Some(&mut cache2)).unwrap();
    }
    let m2 = cache2.manifest();
    // After invalidation, handler.go's manifest entry is dropped,
    // so the next read will re-parse it from scratch.
    let handler_key = m2
        .files
        .keys()
        .find(|k| k.ends_with("pkg/handler.go"))
        .cloned();
    assert!(
        handler_key.is_none(),
        "handler.go should have been cascade-invalidated; still in manifest: {handler_key:?}"
    );
    // db.go was rescanned and is back in the manifest.
    assert!(
        m2.files.keys().any(|k| k.ends_with("pkg/db/db.go")),
        "db.go should be re-tracked after re-scan"
    );

    // discover_cache_dir should locate the existing cache root.
    let found = discover_cache_dir(&root.join("pkg"));
    assert_eq!(found, Some(root.join(DEFAULT_CACHE_DIR)));
}
