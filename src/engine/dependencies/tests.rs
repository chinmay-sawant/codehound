#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::engine::dependencies::go_module_prefix;

    #[test]
    fn go_module_prefix_parses_simple_directive() {
        let tmp = tempfile_root("go-mod-prefix");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("go.mod"), "module github.com/foo/bar\n\ngo 1.22\n").unwrap();
        assert_eq!(
            go_module_prefix(&tmp),
            Some("github.com/foo/bar".to_string())
        );
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn go_module_prefix_returns_none_when_missing() {
        let tmp = tempfile_root("go-mod-missing");
        std::fs::create_dir_all(&tmp).unwrap();
        assert_eq!(go_module_prefix(&tmp), None);
        std::fs::remove_dir_all(&tmp).unwrap();
    }

    fn tempfile_root(label: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("slopguard-deps-{label}-{unique}"))
    }
}
