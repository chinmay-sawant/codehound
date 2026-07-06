//! BP-26..BP-35 — API design bad practices.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use tree_sitter::Node;

use super::super::common::{is_flat_materialized_fixture, is_test_file};
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::rules::Finding;

pub(crate) fn detect_bp_26_context_not_first_parameter(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_functions_and_methods(unit, |function, src| {
        let name = declaration_name(function, src)?;
        if !is_exported_api(function, src, name) {
            return None;
        }
        let params = function.child_by_field_name("parameters")?;
        let mut cursor = params.walk();
        let declarations: Vec<Node> = params
            .named_children(&mut cursor)
            .filter(|child| child.kind().contains("parameter"))
            .collect();
        if declarations.is_empty() {
            return None;
        }
        let has_context = declarations.iter().any(|param| {
            node_text(*param, src).is_some_and(|text| text.contains("context.Context"))
        });
        let first_is_context = declarations
            .first()
            .and_then(|param| node_text(*param, src))
            .is_some_and(|text| text.contains("context.Context"));
        if has_context && !first_is_context {
            Some((
                function.start_byte(),
                "exported API should accept context.Context as its first parameter",
            ))
        } else {
            None
        }
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_26_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_27_exported_function_returns_unexported_type(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    walk_functions_and_methods(unit, |function, src| {
        let name = declaration_name(function, src)?;
        if !is_exported_api(function, src, name) {
            return None;
        }
        let result = function.child_by_field_name("result")?;
        let returned = first_result_type(node_text(result, src)?)?;
        if looks_like_unexported_local_type(returned) {
            Some((
                function.start_byte(),
                "exported API returns a package-private concrete type",
            ))
        } else {
            None
        }
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_27_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_28_single_method_interface(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    walk_type_specs(unit, |spec, src| {
        let count = interface_method_count(spec, src)?;
        (count == 1).then_some((
            spec.start_byte(),
            "single-method interface may be simpler as a function type",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_28_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_29_interface_bloat(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    walk_type_specs(unit, |spec, src| {
        let count = interface_method_count(spec, src)?;
        (count > 5).then_some((
            spec.start_byte(),
            "interface declares more than five methods and is likely too broad",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_29_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_30_exported_interface_without_same_package_impl(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    let package_methods = package_method_sets(unit);
    walk_type_specs(unit, |spec, src| {
        let name = declaration_name(spec, src)?;
        if !is_exported(name) {
            return None;
        }
        let spec_text = node_text(spec, src)?;
        if !spec_text.contains("interface") {
            return None;
        }
        let methods = interface_method_names(spec_text);
        if methods.is_empty() {
            return None;
        }
        let has_impl = package_methods
            .values()
            .any(|implemented| methods.iter().all(|method| implemented.contains(method)));
        (!has_impl).then_some((
            spec.start_byte(),
            "exported interface has no evident same-package implementation",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_30_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_31_constructor_returns_concrete_type(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    let package_methods = package_method_sets(unit);
    let interfaces = package_exported_interfaces(unit);
    walk_functions_and_methods(unit, |function, src| {
        let name = declaration_name(function, src)?;
        if !looks_like_constructor(name) || !is_exported_api(function, src, name) {
            return None;
        }
        let result = function.child_by_field_name("result")?;
        let returned = first_result_type(node_text(result, src)?)?;
        if !is_exported(returned) {
            return None;
        }
        let methods = package_methods.get(returned)?;
        let exposes_interface = interfaces.iter().any(|(iface_name, iface_methods)| {
            iface_name != returned
                && !iface_methods.is_empty()
                && iface_methods.iter().all(|method| methods.contains(method))
        });
        exposes_interface.then_some((
            function.start_byte(),
            "constructor returns a concrete type even though the package already exposes a fitting interface",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_31_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_32_string_alias_error_type(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    let src = unit.source.as_bytes();
    let aliases = collect_string_aliases(unit.tree.root_node(), src);
    if aliases.is_empty() {
        return;
    }
    let error_receivers = collect_error_method_receivers(unit.tree.root_node(), src);
    for (type_name, byte) in aliases {
        if error_receivers.contains(&type_name) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_32_META,
                byte,
                "error type is a string alias instead of a structured type",
            );
        }
    }
}

pub(crate) fn detect_bp_33_sentinel_error_without_is_method(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) {
        return;
    }
    let src = unit.source.as_bytes();
    let error_receivers = collect_error_method_receivers(unit.tree.root_node(), src);
    if error_receivers.is_empty() {
        return;
    }
    let is_receivers = collect_named_method_receivers(unit.tree.root_node(), src, "Is");
    for (type_name, byte) in collect_sentinel_error_types(unit, &error_receivers) {
        if !is_receivers.contains(&type_name) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_33_META,
                byte,
                "sentinel-style error type is missing an Is(error) bool method",
            );
        }
    }
}

pub(crate) fn detect_bp_34_error_wrapping_without_percent_w(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    walk_call_expressions(unit, |call, src| {
        if function_text(call, src) != Some("fmt.Errorf") {
            return None;
        }
        let args = call.child_by_field_name("arguments")?;
        let mut cursor = args.walk();
        let arguments: Vec<Node> = args.named_children(&mut cursor).collect();
        let format_arg = arguments.first().and_then(|node| node_text(*node, src))?;
        if format_arg.contains("%w") || (!format_arg.contains("%v") && !format_arg.contains("%s")) {
            return None;
        }
        let wraps_err = arguments
            .iter()
            .skip(1)
            .filter_map(|node| node_text(*node, src))
            .any(looks_like_error_expr);
        wraps_err.then_some((
            call.start_byte(),
            "fmt.Errorf should wrap errors with %w instead of %v or %s",
        ))
    })
    .into_iter()
    .for_each(|(byte, message)| {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_34_META,
            byte,
            message,
        );
    });
}

pub(crate) fn detect_bp_35_package_name_directory_mismatch(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_test_file(unit) || is_flat_materialized_fixture(unit) {
        return;
    }
    let Some(package) = package_name(unit) else {
        return;
    };
    if package == "main" {
        return;
    }
    let Some(dir_name) = unit
        .path
        .parent()
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
    else {
        return;
    };
    if package != dir_name {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_35_META,
            0,
            "package name diverges from its directory name",
        );
    }
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

fn walk_type_specs(
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
        if node.kind() == "type_spec"
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

fn walk_call_expressions(
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
        if node.kind() == "call_expression"
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

fn declaration_name<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("name")?.utf8_text(src).ok()
}

fn function_text<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.child_by_field_name("function")?.utf8_text(src).ok()
}

fn node_text<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    node.utf8_text(src).ok()
}

fn interface_method_count(spec: Node, src: &[u8]) -> Option<usize> {
    let text = node_text(spec, src)?;
    if !text.contains("interface") {
        return None;
    }
    let mut count = 0;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed == "}"
            || trimmed.starts_with("type ")
            || trimmed.contains("interface {")
            || trimmed.starts_with("interface")
            || trimmed.starts_with("//")
        {
            continue;
        }
        count += 1;
    }
    Some(count)
}

fn collect_string_aliases(root: Node, src: &[u8]) -> HashMap<String, usize> {
    let mut aliases = HashMap::new();

    fn walk(node: Node, src: &[u8], aliases: &mut HashMap<String, usize>) {
        if node.kind() == "type_spec"
            && let Some(name) = declaration_name(node, src)
            && let Some(type_node) = node.child_by_field_name("type")
            && node_text(type_node, src) == Some("string")
        {
            aliases.insert(name.to_string(), node.start_byte());
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, aliases);
        }
    }

    walk(root, src, &mut aliases);
    aliases
}

fn collect_error_method_receivers(root: Node, src: &[u8]) -> HashSet<String> {
    collect_named_method_receivers(root, src, "Error")
}

fn collect_named_method_receivers(root: Node, src: &[u8], method_name: &str) -> HashSet<String> {
    let mut receivers = HashSet::new();

    fn walk(node: Node, src: &[u8], method_name: &str, receivers: &mut HashSet<String>) {
        if node.kind() == "method_declaration"
            && declaration_name(node, src) == Some(method_name)
            && let Some(receiver) = receiver_type_name(node, src)
        {
            receivers.insert(receiver.to_string());
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, method_name, receivers);
        }
    }

    walk(root, src, method_name, &mut receivers);
    receivers
}

fn collect_sentinel_error_types(
    unit: &ParsedUnit,
    error_receivers: &HashSet<String>,
) -> Vec<(String, usize)> {
    let source = unit.source.as_ref();
    let mut found = Vec::new();
    for error_type in error_receivers {
        let needle = format!(" {error_type}");
        let constructor = format!("{error_type}(");
        for (line_no, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with("var Err") && !trimmed.starts_with("const Err") {
                continue;
            }
            if trimmed.contains(&needle) || trimmed.contains(&constructor) {
                found.push((
                    error_type.clone(),
                    super::helpers::line_start_byte(source, line_no),
                ));
                break;
            }
        }
    }
    found
}

fn receiver_type_name<'a>(node: Node<'a>, src: &'a [u8]) -> Option<&'a str> {
    let receiver = node.child_by_field_name("receiver")?;
    let text = receiver.utf8_text(src).ok()?.trim();
    let inner = text.trim_start_matches('(').trim_end_matches(')');
    let ty = inner.split_whitespace().last()?;
    normalize_type_identifier(ty)
}

fn normalize_type_identifier(text: &str) -> Option<&str> {
    let trimmed = text
        .trim()
        .trim_start_matches('*')
        .trim_start_matches("[]")
        .trim_start_matches('&');
    if trimmed.is_empty() || trimmed.contains(' ') {
        return None;
    }
    let identifier = trimmed.rsplit('.').next().unwrap_or(trimmed);
    identifier
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
        .then_some(identifier)
}

fn first_result_type(text: &str) -> Option<&str> {
    let trimmed = text.trim().trim_start_matches('(').trim_end_matches(')');
    let first = trimmed.split(',').next()?.trim();
    normalize_type_identifier(first)
}

fn looks_like_unexported_local_type(name: &str) -> bool {
    if matches!(
        name,
        "error"
            | "string"
            | "bool"
            | "byte"
            | "rune"
            | "int"
            | "int8"
            | "int16"
            | "int32"
            | "int64"
            | "uint"
            | "uint8"
            | "uint16"
            | "uint32"
            | "uint64"
            | "uintptr"
            | "float32"
            | "float64"
            | "complex64"
            | "complex128"
    ) {
        return false;
    }
    name.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_lowercase())
}

fn looks_like_error_expr(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed == "err"
        || trimmed.ends_with(".Err")
        || trimmed.ends_with(".err")
        || trimmed.contains("error")
}

fn package_name(unit: &ParsedUnit) -> Option<String> {
    fn walk(node: Node, src: &[u8]) -> Option<String> {
        if node.kind() == "package_clause" {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if let Ok(text) = child.utf8_text(src)
                    && text != "package"
                {
                    return Some(text.to_string());
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(found) = walk(child, src) {
                return Some(found);
            }
        }
        None
    }

    walk(unit.tree.root_node(), unit.source.as_bytes())
}

fn is_exported(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_uppercase())
}

fn looks_like_constructor(name: &str) -> bool {
    matches!(
        name,
        value if value.starts_with("New")
            || value.starts_with("Open")
            || value.starts_with("Create")
            || value.starts_with("Build")
    )
}

fn package_method_sets(unit: &ParsedUnit) -> HashMap<String, HashSet<String>> {
    let mut methods = HashMap::new();
    for (_, text) in package_file_texts(unit) {
        collect_method_sets_from_text(&text, &mut methods);
    }
    methods
}

fn package_exported_interfaces(unit: &ParsedUnit) -> Vec<(String, HashSet<String>)> {
    let mut interfaces = Vec::new();
    for (_, text) in package_file_texts(unit) {
        interfaces.extend(collect_exported_interfaces_from_text(&text));
    }
    interfaces
}

fn package_file_texts(unit: &ParsedUnit) -> Vec<(PathBuf, String)> {
    let Some(dir) = unit.path.parent() else {
        return Vec::new();
    };
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return files;
    };
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

fn collect_method_sets_from_text(source: &str, out: &mut HashMap<String, HashSet<String>>) {
    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("func (") {
            continue;
        }
        let Some(receiver_end) = trimmed.find(')') else {
            continue;
        };
        let receiver = trimmed["func (".len()..receiver_end].trim();
        let receiver_type = receiver
            .split_whitespace()
            .last()
            .unwrap_or("")
            .trim_start_matches('*');
        let rest = trimmed[receiver_end + 1..].trim();
        let Some(method_name) = rest.split('(').next().map(str::trim) else {
            continue;
        };
        if receiver_type.is_empty() || method_name.is_empty() {
            continue;
        }
        out.entry(receiver_type.to_string())
            .or_default()
            .insert(method_name.to_string());
    }
}

fn collect_exported_interfaces_from_text(source: &str) -> Vec<(String, HashSet<String>)> {
    let mut interfaces = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        let trimmed = lines[idx].trim();
        if let Some(rest) = trimmed.strip_prefix("type ")
            && let Some((name, suffix)) = rest.split_once(' ')
            && is_exported(name)
            && suffix.contains("interface")
        {
            let mut block = String::from(trimmed);
            idx += 1;
            while idx < lines.len() {
                let next = lines[idx];
                block.push('\n');
                block.push_str(next);
                if next.trim() == "}" {
                    break;
                }
                idx += 1;
            }
            let methods = interface_method_names(&block);
            if !methods.is_empty() {
                interfaces.push((name.to_string(), methods));
            }
        }
        idx += 1;
    }
    interfaces
}

fn interface_method_names(text: &str) -> HashSet<String> {
    let mut methods = HashSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed == "}"
            || trimmed.starts_with("type ")
            || trimmed.contains("interface {")
            || trimmed.starts_with("//")
        {
            continue;
        }
        if let Some(name) = trimmed.split('(').next().map(str::trim)
            && !name.is_empty()
            && name
                .chars()
                .next()
                .is_some_and(|ch| ch.is_ascii_alphabetic())
        {
            methods.insert(name.to_string());
        }
    }
    methods
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
