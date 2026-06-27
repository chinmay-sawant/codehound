#![cfg(feature = "go")]
#![allow(unused_imports)]

#[test]
#[ignore]
fn debug_dependency_extraction() {
    // Sanity test against a real on-disk project. Useful as a
    // manual smoke check; not part of the standard suite because
    // it depends on the gopdfsuit checkout existing at a fixed path.
    use slopguard::core::LanguagePlugin;
    use slopguard::engine::{discover_project_root, extract_dependencies, go_module_prefix};
    use slopguard::lang::go::GoPlugin;
    use std::sync::Arc;

    let project = discover_project_root(std::path::Path::new(
        "/home/chinmay/ChinmayPersonalProjects/gopdfsuit",
    ));
    let module = go_module_prefix(&project);
    eprintln!("project_root: {project:?}");
    eprintln!("module_prefix: {module:?}");

    let path = project.join("pkg/gopdflib/redact.go");
    let source = std::fs::read_to_string(&path).expect("read source");
    let plugin = GoPlugin;
    let mut parser = tree_sitter::Parser::new();
    plugin
        .configure_parser(&mut parser)
        .expect("configure Go parser");
    let unit = plugin
        .parse_with(&mut parser, &path, Arc::from(source.as_str()))
        .expect("parse");
    let deps = extract_dependencies(&unit, &project, module.as_deref());
    eprintln!("deps for redact.go: {deps:#?}");
    // This file imports two local packages, so it should have deps.
    assert!(!deps.is_empty(), "expected deps for redact.go");
}

#[test]
#[ignore]
fn debug_discover_project_root() {
    use slopguard::engine::discover_project_root;
    let tmp = std::env::temp_dir().join("slopguard-test-no-git-here");
    std::fs::create_dir_all(&tmp).unwrap();
    let discovered = discover_project_root(&tmp);
    eprintln!("discovered for {tmp:?}: {discovered:?}");
    let with_git = std::env::temp_dir().join("slopguard-test-with-git");
    std::fs::create_dir_all(with_git.join(".git")).unwrap();
    let discovered2 = discover_project_root(&with_git);
    eprintln!("discovered for {with_git:?}: {discovered2:?}");
    std::fs::remove_dir_all(&tmp).unwrap();
    std::fs::remove_dir_all(&with_git).unwrap();
}
