#[cfg(test)]
mod go_module_prefix_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::engine::dependencies::go_module_prefix;

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock before UNIX epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("codehound-deps-{label}-{unique}"));
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn go_module_prefix_parses_simple_directive() {
        let tmp_dir = TempDir::new("go-mod-prefix");
        let tmp = &tmp_dir.path;
        std::fs::create_dir_all(tmp).expect("create temp dir");
        std::fs::write(tmp.join("go.mod"), "module github.com/foo/bar\n\ngo 1.22\n")
            .expect("write go.mod");
        assert_eq!(
            go_module_prefix(tmp),
            Some("github.com/foo/bar".to_string())
        );
    }

    #[test]
    fn go_module_prefix_returns_none_when_missing() {
        let tmp_dir = TempDir::new("go-mod-missing");
        let tmp = &tmp_dir.path;
        std::fs::create_dir_all(tmp).expect("create temp dir");
        assert_eq!(go_module_prefix(tmp), None);
    }
}
