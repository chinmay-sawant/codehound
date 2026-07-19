use std::borrow::Cow;

use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

pub fn finding(rule_id: &'static str, file: &str, line: usize, column: usize) -> Finding {
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

#[cfg(feature = "go")]
pub mod dep_helpers {
    use std::path::Path;
    use std::sync::Arc;

    use codehound::core::LanguagePlugin;
    use codehound::engine::extract_dependencies;
    use codehound::lang::go::GoPlugin;

    pub fn write_file(path: &Path, body: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, body).unwrap();
    }

    pub fn parse_go(project: &Path, rel: &str) -> codehound::core::ParsedUnit {
        let path = project.join(rel);
        let source = std::fs::read_to_string(&path).unwrap();
        let plugin = GoPlugin;
        let mut parser = tree_sitter::Parser::new();
        plugin
            .configure_parser(&mut parser)
            .expect("configure Go parser");
        plugin
            .parse_with(&mut parser, &path, Arc::from(source.as_str()))
            .unwrap()
    }

    pub fn deps_for(project: &Path, rel: &str) -> Vec<String> {
        let unit = parse_go(project, rel);
        // Plugin derives Go module prefix from project root; engine only
        // passes the language-neutral root.
        extract_dependencies(&unit, project)
    }
}
