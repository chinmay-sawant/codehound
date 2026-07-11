#[cfg(test)]
mod t {
    use std::borrow::Cow;

    use crate::rules::{Finding, FindingInputs, LineCol, Severity};

    use super::super::{CacheStore, cache_key_for_path, content_hash};

    fn finding(rule_id: &'static str, file: &str, line: usize, column: usize) -> Finding {
        Finding::new(FindingInputs::new(
            rule_id,
            "title",
            file,
            LineCol { line, column },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        ))
    }

    #[test]
    fn in_memory_total_size_tracks_inserted_bytes() {
        let mut store = CacheStore::in_memory();
        let bulky_message = "x".repeat(8_000);
        for i in 0..5 {
            let name = format!("file{i:03}.go");
            let mut f = finding("CWE-78", &name, 1, 1);
            f.message = bulky_message.clone();
            store
                .put(
                    &name,
                    &content_hash(&name),
                    &[],
                    vec![f],
                    &format!("2026-06-10T00:{i:02}:00Z"),
                )
                .unwrap();
        }

        let total = store.total_size();
        assert!(
            total > 0,
            "in-memory total_size should be non-zero after puts"
        );
        assert_eq!(store.len(), 5);
    }

    #[test]
    fn content_hash_format_is_stable() {
        let h = content_hash("hello");
        assert!(h.starts_with("sha256:"));
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(
            h,
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn cache_key_for_path_is_stable() {
        assert_eq!(
            cache_key_for_path("a/b/c.go"),
            cache_key_for_path("a/b/c.go")
        );
    }

    #[test]
    fn cache_key_normalizes_backslashes() {
        assert_eq!(
            cache_key_for_path("a\\b\\c.go"),
            cache_key_for_path("a/b/c.go")
        );
    }

    #[test]
    fn put_normalizes_manifest_keys_and_deps() {
        let mut store = CacheStore::in_memory();
        store
            .put(
                r".\pkg\handler.go",
                "sha256:abc",
                &[r"pkg\db.go".to_string(), "./pkg/util.go".to_string()],
                vec![finding("CWE-78", "pkg/handler.go", 1, 1)],
                "2026-07-11T00:00:00Z",
            )
            .unwrap();
        let keys: Vec<_> = store.manifest().files.keys().cloned().collect();
        assert_eq!(keys, vec!["pkg/handler.go".to_string()]);
        let meta = store.manifest().files.get("pkg/handler.go").unwrap();
        assert!(meta.dependencies.iter().any(|d| d == "pkg/db.go"));
        assert!(meta.dependencies.iter().any(|d| d == "pkg/util.go"));
    }

    #[test]
    fn expand_dirty_fixpoint_marks_dependents() {
        let mut store = CacheStore::in_memory();
        store
            .put(
                "pkg/db.go",
                "sha256:db1",
                &[],
                vec![finding("CWE-78", "pkg/db.go", 1, 1)],
                "2026-07-11T00:00:00Z",
            )
            .unwrap();
        store
            .put(
                "pkg/handler.go",
                "sha256:h1",
                &["pkg/db.go".to_string()],
                vec![finding("CWE-78", "pkg/handler.go", 1, 1)],
                "2026-07-11T00:00:00Z",
            )
            .unwrap();
        let mut dirty = std::collections::HashSet::from(["pkg/db.go".to_string()]);
        store.expand_dirty_fixpoint(&mut dirty);
        assert!(dirty.contains("pkg/db.go"));
        assert!(
            dirty.contains("pkg/handler.go"),
            "handler must be dirty via reverse dep edge: {dirty:?}"
        );
    }

    #[test]
    fn mass_stale_clears_all_entries() {
        let mut store = CacheStore::in_memory();
        store
            .put(
                "a.go",
                "sha256:a",
                &[],
                vec![finding("CWE-78", "a.go", 1, 1)],
                "2026-07-11T00:00:00Z",
            )
            .unwrap();
        assert_eq!(store.len(), 1);
        store.mass_stale_for_tool_version();
        assert_eq!(store.len(), 0);
        assert_eq!(store.manifest().tool_version, env!("CARGO_PKG_VERSION"));
    }
}
