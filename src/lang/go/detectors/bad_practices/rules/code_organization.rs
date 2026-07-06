//! BP-36..BP-45 — code-organization bad practices.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use tree_sitter::Node;

use super::super::common::{is_flat_materialized_fixture, is_test_file};
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

pub(crate) fn detect_bp_36_init_with_side_effects(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    for (byte, message) in walk_functions_and_methods(unit, |function, src| {
        if declaration_name(function, src) != Some("init") {
            return None;
        }
        let body = function.child_by_field_name("body")?;
        contains_kind(
            body,
            &["call_expression", "go_statement", "defer_statement"],
        )
        .then_some((
            function.start_byte(),
            "init() performs side effects beyond simple package setup",
        ))
    }) {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_36_META,
            byte,
            message,
        );
    }
}

pub(crate) fn detect_bp_37_package_level_mutable_global(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    for (byte, message) in walk_top_level_nodes(unit, |node, src| {
        if node.kind() != "var_declaration" {
            return None;
        }
        let names = collect_declared_names(node, src, "var_spec");
        if !names.is_empty() && names.iter().all(|name| name.starts_with("Err")) {
            return None;
        }
        let text = node_text(node, src)?;
        (!text.contains("const")).then_some((
            node.start_byte(),
            "package-level mutable global state makes behavior harder to reason about",
        ))
    }) {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_37_META,
            byte,
            message,
        );
    }
}

pub(crate) fn detect_bp_38_unused_unexported_helper(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    let src = unit.source.as_bytes();
    let local_calls = collect_local_calls(unit.tree.root_node(), src);
    for (name, byte) in collect_unexported_helpers(unit.tree.root_node(), src) {
        if !local_calls.contains(name.as_str()) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_38_META,
                byte,
                "unexported helper has no same-file callers",
            );
        }
    }
}

pub(crate) fn detect_bp_39_exported_function_without_doc_comment(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    for (byte, message) in walk_functions_and_methods(unit, |function, src| {
        let name = declaration_name(function, src)?;
        if !is_exported_api(function, src, name) || has_doc_comment(unit, function, name) {
            return None;
        }
        Some((
            function.start_byte(),
            "exported API should have a doc comment that starts with its name",
        ))
    }) {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_39_META,
            byte,
            message,
        );
    }
}

pub(crate) fn detect_bp_40_unrelated_constants_in_one_block(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    for (byte, message) in walk_top_level_nodes(unit, |node, src| {
        if node.kind() != "const_declaration" {
            return None;
        }
        let names = collect_declared_names(node, src, "const_spec");
        if names.len() < 3 {
            return None;
        }
        let prefixes: HashSet<String> = names.iter().map(|name| constant_prefix(name)).collect();
        (prefixes.len() > 2).then_some((
            node.start_byte(),
            "const block groups unrelated constants together",
        ))
    }) {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_40_META,
            byte,
            message,
        );
    }
}

pub(crate) fn detect_bp_41_missing_package_doc_comment(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) || is_flat_materialized_fixture(unit) || !is_package_anchor(unit) {
        return;
    }
    let Some(package) = package_name(unit) else {
        return;
    };
    let has_doc = package_file_texts(unit)
        .into_iter()
        .any(|(_, text)| has_package_doc_comment(&text, package));
    if !has_doc {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_41_META,
            0,
            "package is missing a package-level doc comment",
        );
    }
}

pub(crate) fn detect_bp_42_one_off_import_alias(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    let source = unit.source.as_ref();
    for (byte, alias) in collect_import_aliases(unit.tree.root_node(), unit.source.as_bytes()) {
        if alias == "_" || alias == "." {
            continue;
        }
        if count_word_occurrences(source, &alias) <= 2 {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_42_META,
                byte,
                "import alias is only used once and likely adds indirection without value",
            );
        }
    }
}

pub(crate) fn detect_bp_43_dot_import_outside_tests(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    for (byte, alias) in collect_import_aliases(unit.tree.root_node(), unit.source.as_bytes()) {
        if alias == "." {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_43_META,
                byte,
                "dot imports outside tests hide where identifiers come from",
            );
        }
    }
}

pub(crate) fn detect_bp_44_blank_import_without_justification(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    let source = unit.source.as_ref();
    for (byte, path, line_no) in
        collect_blank_imports(unit.tree.root_node(), unit.source.as_bytes())
    {
        if is_allowed_blank_import(&path) || has_blank_import_justification(source, line_no) {
            continue;
        }
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_44_META,
            byte,
            "blank import should carry a justification or match a standard registration pattern",
        );
    }
}

pub(crate) fn detect_bp_45_inconsistent_receiver_name(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    let src = unit.source.as_bytes();
    let mut by_type: HashMap<String, String> = HashMap::new();
    for (type_name, receiver_name, byte) in collect_method_receivers(unit.tree.root_node(), src) {
        if let Some(previous) = by_type.get(&type_name) {
            if previous != &receiver_name {
                push_at(
                    unit,
                    out,
                    &crate::lang::go::detectors::bad_practices::BP_45_META,
                    byte,
                    "methods on the same receiver type should use a consistent receiver name",
                );
            }
        } else {
            by_type.insert(type_name, receiver_name);
        }
    }
}

fn is_package_anchor(unit: &ParsedUnit) -> bool {
    package_file_texts(unit)
        .first()
        .is_some_and(|(path, _)| path == &unit.path)
}

fn package_file_texts(unit: &ParsedUnit) -> Vec<(PathBuf, String)> {
    let Some(dir) = unit.path.parent() else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("go") {
            continue;
        }
        if path.to_string_lossy().ends_with("_test.go") {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&path) {
            files.push((path, text));
        }
    }
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn package_name(unit: &ParsedUnit) -> Option<&str> {
    for line in unit.source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("package ") {
            return Some(rest.trim());
        }
    }
    None
}

fn has_package_doc_comment(text: &str, package: &str) -> bool {
    let mut comments = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            comments.push(trimmed.trim_start_matches("//").trim().to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("package ") {
            return rest.trim() == package
                && comments
                    .last()
                    .is_some_and(|comment| comment.starts_with(&format!("Package {package}")));
        }
        if trimmed.is_empty() {
            continue;
        }
        comments.clear();
    }
    false
}

fn walk_functions_and_methods(
    unit: &ParsedUnit,
    mut visit: impl FnMut(Node, &[u8]) -> Option<(usize, &'static str)>,
) -> Vec<(usize, &'static str)> {
    let mut findings = Vec::new();

    fn walk(
        node: Node,
        src: &[u8],
        findings: &mut Vec<(usize, &'static str)>,
        visit: &mut impl FnMut(Node, &[u8]) -> Option<(usize, &'static str)>,
    ) {
        if matches!(node.kind(), "function_declaration" | "method_declaration")
            && let Some(finding) = visit(node, src)
        {
            findings.push(finding);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, findings, visit);
        }
    }

    walk(
        unit.tree.root_node(),
        unit.source.as_bytes(),
        &mut findings,
        &mut visit,
    );
    findings
}

fn walk_top_level_nodes(
    unit: &ParsedUnit,
    mut visit: impl FnMut(Node, &[u8]) -> Option<(usize, &'static str)>,
) -> Vec<(usize, &'static str)> {
    let mut findings = Vec::new();
    let root = unit.tree.root_node();
    let mut cursor = root.walk();
    for child in root.named_children(&mut cursor) {
        if let Some(finding) = visit(child, unit.source.as_bytes()) {
            findings.push(finding);
        }
    }
    findings
}

fn declaration_name<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("name")?.utf8_text(src).ok()
}

fn node_text<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.utf8_text(src).ok()
}

fn is_exported(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
}

fn is_exported_api(node: Node, src: &[u8], name: &str) -> bool {
    if !is_exported(name) {
        return false;
    }
    if node.kind() != "method_declaration" {
        return true;
    }
    receiver_type_name(node, src).is_some_and(is_exported)
}

fn looks_like_helper_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    lowered == "helper"
        || lowered.starts_with("helper")
        || lowered.starts_with("must")
        || lowered.starts_with("build")
        || lowered.starts_with("parse")
}

fn contains_kind(node: Node, wanted: &[&str]) -> bool {
    fn walk(node: Node, wanted: &[&str]) -> bool {
        if wanted.contains(&node.kind()) {
            return true;
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if walk(child, wanted) {
                return true;
            }
        }
        false
    }
    walk(node, wanted)
}

fn collect_local_calls(root: Node, src: &[u8]) -> HashSet<String> {
    let mut calls = HashSet::new();

    fn walk(node: Node, src: &[u8], calls: &mut HashSet<String>) {
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
            && let Ok(text) = function.utf8_text(src)
            && is_local_function_name(text)
        {
            calls.insert(text.to_string());
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, calls);
        }
    }

    walk(root, src, &mut calls);
    calls
}

fn is_local_function_name(text: &str) -> bool {
    text.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && !text.contains('.')
}

fn collect_unexported_helpers(root: Node, src: &[u8]) -> Vec<(String, usize)> {
    let mut helpers = Vec::new();

    fn walk(node: Node, src: &[u8], helpers: &mut Vec<(String, usize)>) {
        if matches!(node.kind(), "function_declaration" | "method_declaration")
            && let Some(name) = declaration_name(node, src)
            && name != "init"
            && name != "main"
            && !name.starts_with("Test")
            && !name.starts_with("Benchmark")
            && !name.starts_with("Example")
            && !is_exported(name)
            && looks_like_helper_name(name)
        {
            helpers.push((name.to_string(), node.start_byte()));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, helpers);
        }
    }

    walk(root, src, &mut helpers);
    helpers
}

fn has_doc_comment(unit: &ParsedUnit, node: Node, name: &str) -> bool {
    let (line, _) = unit.line_col(node.start_byte());
    if line <= 1 {
        return false;
    }
    let lines: Vec<&str> = unit.source.lines().collect();
    let mut idx = line.saturating_sub(2);
    let mut comments = Vec::new();
    while let Some(text) = lines.get(idx) {
        let trimmed = text.trim();
        if trimmed.starts_with("//") {
            comments.push(trimmed.trim_start_matches("//").trim().to_string());
        } else if trimmed.is_empty() {
            break;
        } else {
            return false;
        }
        if idx == 0 {
            break;
        }
        idx -= 1;
    }
    comments.reverse();
    comments
        .first()
        .is_some_and(|comment| comment.starts_with(name))
}

fn collect_declared_names(node: Node, src: &[u8], wanted_spec: &str) -> Vec<String> {
    let mut names = Vec::new();

    fn walk(node: Node, src: &[u8], wanted_spec: &str, names: &mut Vec<String>) {
        if node.kind() == wanted_spec {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() == "identifier"
                    && let Ok(text) = child.utf8_text(src)
                {
                    names.push(text.to_string());
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, wanted_spec, names);
        }
    }

    walk(node, src, wanted_spec, &mut names);
    names
}

fn constant_prefix(name: &str) -> String {
    if let Some((prefix, _)) = name.split_once('_') {
        return prefix.to_string();
    }
    let mut prefix = String::new();
    for ch in name.chars() {
        if ch.is_ascii_uppercase() && !prefix.is_empty() {
            break;
        }
        prefix.push(ch);
    }
    if prefix.is_empty() {
        name.to_string()
    } else {
        prefix
    }
}

fn collect_import_aliases(root: Node, src: &[u8]) -> Vec<(usize, String)> {
    let mut aliases = Vec::new();

    fn walk(node: Node, src: &[u8], aliases: &mut Vec<(usize, String)>) {
        if node.kind() == "import_spec"
            && let Some(name) = node.child_by_field_name("name")
            && let Ok(text) = name.utf8_text(src)
        {
            aliases.push((node.start_byte(), text.to_string()));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, aliases);
        }
    }

    walk(root, src, &mut aliases);
    aliases
}

fn count_word_occurrences(source: &str, word: &str) -> usize {
    source
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter(|token| *token == word)
        .count()
}

fn collect_blank_imports(root: Node, src: &[u8]) -> Vec<(usize, String, usize)> {
    let mut imports = Vec::new();

    fn walk(node: Node, src: &[u8], imports: &mut Vec<(usize, String, usize)>) {
        if node.kind() == "import_spec"
            && let Some(name) = node.child_by_field_name("name")
            && name.utf8_text(src).ok() == Some("_")
            && let Some(path) = node.child_by_field_name("path")
            && let Ok(text) = path.utf8_text(src)
        {
            let line_no = src[..node.start_byte()]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count();
            imports.push((
                node.start_byte(),
                text.trim_matches('"').trim_matches('`').to_string(),
                line_no,
            ));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, imports);
        }
    }

    walk(root, src, &mut imports);
    imports
}

fn is_allowed_blank_import(path: &str) -> bool {
    path.starts_with("image/")
        || path.contains("driver")
        || path.ends_with("/pprof")
        || path.contains("plugin")
}

fn has_blank_import_justification(source: &str, line_no: usize) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let current = lines.get(line_no).copied().unwrap_or_default();
    let previous = line_no
        .checked_sub(1)
        .and_then(|idx| lines.get(idx).copied())
        .unwrap_or_default();
    let context = format!("{previous}\n{current}").to_ascii_lowercase();
    context.contains("register")
        || context.contains("side effect")
        || context.contains("side-effect")
        || context.contains("plugin")
}

fn collect_method_receivers(root: Node, src: &[u8]) -> Vec<(String, String, usize)> {
    let mut receivers = Vec::new();

    fn walk(node: Node, src: &[u8], receivers: &mut Vec<(String, String, usize)>) {
        if node.kind() == "method_declaration"
            && let Some(receiver) = node.child_by_field_name("receiver")
        {
            let text = receiver.utf8_text(src).ok().map(str::trim).unwrap_or("");
            let inner = text.trim_start_matches('(').trim_end_matches(')');
            let mut parts = inner.split_whitespace();
            let receiver_name = parts.next().map(str::to_string);
            let receiver_type = parts
                .next()
                .map(|value| value.trim_start_matches('*').to_string());
            if let (Some(type_name), Some(name)) = (receiver_type, receiver_name) {
                receivers.push((type_name, name, node.start_byte()));
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, receivers);
        }
    }

    walk(root, src, &mut receivers);
    receivers
}

fn receiver_type_name<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    let receiver = node.child_by_field_name("receiver")?;
    let text = receiver.utf8_text(src).ok()?.trim();
    let inner = text.trim_start_matches('(').trim_end_matches(')');
    inner
        .split_whitespace()
        .last()
        .map(|value| value.trim_start_matches('*'))
}
