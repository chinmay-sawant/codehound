#[cfg(test)]
mod go_module_prefix_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::engine::dependencies::go_module_prefix;

    #[test]
    fn go_module_prefix_parses_simple_directive() {
        let tmp = tempfile_root("go-mod-prefix");
        std::fs::create_dir_all(&tmp).expect("create temp dir");
        std::fs::write(tmp.join("go.mod"), "module github.com/foo/bar\n\ngo 1.22\n")
            .expect("write go.mod");
        assert_eq!(
            go_module_prefix(&tmp),
            Some("github.com/foo/bar".to_string())
        );
        std::fs::remove_dir_all(&tmp).expect("remove temp dir");
    }

    #[test]
    fn go_module_prefix_returns_none_when_missing() {
        let tmp = tempfile_root("go-mod-missing");
        std::fs::create_dir_all(&tmp).expect("create temp dir");
        assert_eq!(go_module_prefix(&tmp), None);
        std::fs::remove_dir_all(&tmp).expect("remove temp dir");
    }

    fn tempfile_root(label: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("codehound-deps-{label}-{unique}"))
    }
}
