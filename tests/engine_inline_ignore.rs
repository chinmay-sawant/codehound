use slopguard::engine::{IgnoreDirective, parse_inline_ignores};

#[test]
fn parse_inline_ignore_single_rule_targets_next_code_line() {
    let ignores = parse_inline_ignores(
        r#"
// slopguard-ignore: CWE-22

value := input
"#,
    );

    assert_eq!(
        ignores.get(&4),
        Some(&IgnoreDirective::rules(vec!["CWE-22".to_string()]))
    );
}

#[test]
fn parse_inline_ignore_multi_rule() {
    let ignores = parse_inline_ignores("//slopguard-ignore:CWE-22, CWE-89\nrun()\n");

    assert_eq!(
        ignores.get(&2),
        Some(&IgnoreDirective::rules(vec![
            "CWE-22".to_string(),
            "CWE-89".to_string()
        ]))
    );
}

#[test]
fn parse_inline_ignore_all_rules() {
    let ignores = parse_inline_ignores("//  slopguard-ignore:  all  \nrun()\n");

    assert_eq!(ignores.get(&2), Some(&IgnoreDirective::all()));
}

#[test]
fn parse_inline_ignore_skips_comment_only_lines() {
    let ignores = parse_inline_ignores(
        r#"
// slopguard-ignore: CWE-22
// explanatory comment
run()
"#,
    );

    assert_eq!(
        ignores.get(&4),
        Some(&IgnoreDirective::rules(vec!["CWE-22".to_string()]))
    );
}

#[test]
fn parse_inline_ignore_ignores_non_matching_comments() {
    let ignores = parse_inline_ignores("// some other comment\nrun()\n");

    assert!(ignores.is_empty());
}

#[cfg(feature = "go")]
#[path = "helpers/mod.rs"]
mod helpers;

#[cfg(feature = "go")]
mod cache_inline {
    use super::helpers;
    use helpers::cache::dep_helpers;
    use helpers::unique_temp_root;

    use std::collections::HashSet;

    use slopguard::engine::{CacheSession, CacheStore, DEFAULT_CACHE_DIR};

    #[test]
    fn inline_ignore_re_applied_on_cache_hit() {
        use dep_helpers::*;
        use slopguard::core::ScanContext;
        use slopguard::engine::Analyzer;

        let root = unique_temp_root("inline-ignore-cache");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
        write_file(
            &root.join("cmd.go"),
            r#"package cmd

import (
    "net/http"
    "os/exec"
)

func Run(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
    _, _ = cmd.CombinedOutput()
}
"#,
        );

        let cache_dir = root.join(DEFAULT_CACHE_DIR);
        let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 500).unwrap();
        let first_count = {
            let analyzer = Analyzer::builder()
                .scan_context(ScanContext::default())
                .build();
            let r = analyzer
                .analyze_paths(&[&root], Some(CacheSession::open(&mut cache)))
                .unwrap();
            r.findings.len()
        };
        cache.flush().unwrap();
        assert!(
            first_count > 0,
            "expected findings on first scan; cache should record the result"
        );

        let mut src = std::fs::read_to_string(root.join("cmd.go")).unwrap();
        src.insert_str(0, "// slopguard-ignore-file: CWE-78\n");
        std::fs::write(root.join("cmd.go"), &src).unwrap();

        let mut cache2 = CacheStore::open_with_capacity(cache_dir, 500).unwrap();
        let (second_count, cwe78_in_second) = {
            let analyzer = Analyzer::builder()
                .scan_context(ScanContext::default())
                .build();
            let r = analyzer
                .analyze_paths(&[&root], Some(CacheSession::open(&mut cache2)))
                .unwrap();
            let cwe78_count = r.findings.iter().filter(|f| f.rule_id == "CWE-78").count();
            (r.findings.len(), cwe78_count)
        };
        assert!(
            cwe78_in_second == 0,
            "inline-ignore on CWE-78 should drop the CWE-78 finding on cache hit, \
             but {cwe78_in_second} remained (total findings: {second_count})"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inline_ignore_applied_on_cache_hit_when_source_unchanged() {
        use dep_helpers::*;
        use slopguard::core::ScanContext;
        use slopguard::engine::Analyzer;

        let root = unique_temp_root("inline-cache-hit");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
        write_file(
            &root.join("cmd.go"),
            "// slopguard-ignore-file: CWE-78\npackage cmd\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nfunc Run(w http.ResponseWriter, r *http.Request) {\n\thost := r.URL.Query().Get(\"host\")\n\tcmd := exec.Command(\"sh\", \"-c\", \"ping -c 1 \"+host)\n\t_, _ = cmd.CombinedOutput()\n}\n",
        );

        let cache_dir = root.join(DEFAULT_CACHE_DIR);
        let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 500).unwrap();
        {
            let analyzer = Analyzer::builder()
                .scan_context(ScanContext::default())
                .build();
            let _ = analyzer
                .analyze_paths(&[&root], Some(CacheSession::open(&mut cache)))
                .unwrap();
        }
        cache.flush().unwrap();

        let mut cache2 = CacheStore::open_with_capacity(cache_dir, 500).unwrap();
        let cwe78 = {
            let analyzer = Analyzer::builder()
                .scan_context(ScanContext::default())
                .build();
            let r = analyzer
                .analyze_paths(&[&root], Some(CacheSession::open(&mut cache2)))
                .unwrap();
            r.findings.iter().filter(|f| f.rule_id == "CWE-78").count()
        };
        assert_eq!(
            cwe78, 0,
            "CWE-78 must be filtered by slopguard-ignore-file on cache hit"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skip_flag_filters_cached_findings() {
        use dep_helpers::*;
        use slopguard::core::ScanContext;
        use slopguard::engine::Analyzer;

        let root = unique_temp_root("skip-cache-hit");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("go.mod"), "module example.com/proj\n\ngo 1.22\n").unwrap();
        write_file(
            &root.join("cmd.go"),
            r#"package cmd

import (
    "net/http"
    "os"
    "os/exec"
)

func Run(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
    _, _ = cmd.CombinedOutput()
}

func ReadFile(r *http.Request) {
    name := r.URL.Query().Get("file")
    data, _ := os.ReadFile(name)
    _ = data
}
"#,
        );

        let cache_dir = root.join(DEFAULT_CACHE_DIR);
        let mut cache = CacheStore::open_with_capacity(cache_dir.clone(), 500).unwrap();

        let first_ids = {
            let analyzer = Analyzer::builder()
                .scan_context(ScanContext::default())
                .build();
            let r = analyzer
                .analyze_paths(&[&root], Some(CacheSession::open(&mut cache)))
                .unwrap();
            let mut ids: Vec<String> = r.findings.iter().map(|f| f.rule_id.to_string()).collect();
            ids.sort();
            ids.dedup();
            ids
        };
        cache.flush().unwrap();
        assert!(
            first_ids.len() > 1,
            "expected at least 2 distinct rule IDs, got {first_ids:?}"
        );

        let skipped_rule = first_ids[0].clone();
        let mut skip_set = HashSet::new();
        skip_set.insert(skipped_rule.clone());

        let mut cache2 = CacheStore::open_with_capacity(cache_dir, 500).unwrap();
        let second_ids = {
            let ctx = ScanContext {
                skip: skip_set,
                ..Default::default()
            };
            let analyzer = Analyzer::builder().scan_context(ctx).build();
            let r = analyzer
                .analyze_paths(&[&root], Some(CacheSession::open(&mut cache2)))
                .unwrap();
            let mut ids: Vec<String> = r.findings.iter().map(|f| f.rule_id.to_string()).collect();
            ids.sort();
            ids.dedup();
            ids
        };

        assert!(
            !second_ids.contains(&skipped_rule),
            "skipped rule {skipped_rule} should not appear on cache hit; got {second_ids:?}"
        );
        assert!(
            second_ids.len() < first_ids.len(),
            "second run (with --skip) should have fewer distinct rule IDs than first run"
        );

        std::fs::remove_dir_all(root).unwrap();
    }
}
