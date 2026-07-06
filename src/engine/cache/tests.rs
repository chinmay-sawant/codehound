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
            let entry = super::super::types::CacheEntry {
                schema_version: super::super::types::CACHE_VERSION,
                file: name.clone(),
                content_hash: content_hash(&name),
                mtime_secs: 0,
                mtime_nanos: 0,
                language: "go".to_string(),
                findings: vec![f],
                dependencies: Vec::new(),
                cached_at: format!("2026-06-10T00:{i:02}:00Z"),
            };
            store.put(entry).unwrap();
        }

        let total = store.total_size();
        assert!(total > 0, "in-memory total_size should be non-zero after puts");
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
}
