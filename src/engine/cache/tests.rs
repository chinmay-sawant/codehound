#[cfg(test)]
mod t {
    use super::super::{cache_key_for_path, content_hash};

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
