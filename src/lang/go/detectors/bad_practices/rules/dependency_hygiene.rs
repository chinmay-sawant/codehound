//! BP-56..BP-65 — dependency-hygiene bad practices.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use tree_sitter::Node;
use walkdir::WalkDir;

use super::super::common::{is_materialized_fixture, is_project_anchor};
use super::super::source_index::SourceIndex;
use super::helpers::push_at;
use crate::core::ParsedUnit;
use crate::engine::discover_project_root;
use crate::rules::Finding;

pub(crate) fn detect_bp_56_deprecated_package_used(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    for (byte, path) in collect_import_paths(unit) {
        if matches!(path.as_str(), "io/ioutil" | "golang.org/x/net/context") {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_56_META,
                byte,
                "deprecated package is imported; prefer the modern stdlib replacement",
            );
        }
    }
}

pub(crate) fn detect_bp_57_stale_go_version_in_go_mod(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    // ponytail: tracks Go's two-release support window as of 2026-07-03.
    const MIN_SUPPORTED_GO_MINOR: u64 = 25;
    let Some((major, minor)) = parse_go_version(&go_mod.text) else {
        return;
    };
    if major == 1 && minor < MIN_SUPPORTED_GO_MINOR {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_57_META,
            0,
            "go.mod targets an out-of-support Go major release; update to a currently supported baseline",
        );
    }
}

pub(crate) fn detect_bp_58_unpinned_dependency_version(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    for require in parse_requires(&go_mod.text) {
        if version_missing_patch(&require.version) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_58_META,
                0,
                "dependency version is pinned only to major/minor; prefer a full module version",
            );
            break;
        }
    }
}

pub(crate) fn detect_bp_59_unused_direct_dependency(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    let imports = collect_project_imports(go_mod.root.as_path());
    for require in parse_requires(&go_mod.text) {
        if require.indirect {
            continue;
        }
        if !imports.all.iter().any(|import| {
            import == &require.module || import.starts_with(&(require.module.clone() + "/"))
        }) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_59_META,
                0,
                "direct dependency in go.mod is not imported by the project",
            );
            break;
        }
    }
}

pub(crate) fn detect_bp_60_test_only_dependency_in_main_go_mod(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    let imports = collect_project_imports(go_mod.root.as_path());
    for require in parse_requires(&go_mod.text) {
        let used_in_tests = imports.test_only.iter().any(|import| {
            import == &require.module || import.starts_with(&(require.module.clone() + "/"))
        });
        let used_in_main = imports.non_test.iter().any(|import| {
            import == &require.module || import.starts_with(&(require.module.clone() + "/"))
        });
        if used_in_tests && !used_in_main {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_60_META,
                0,
                "dependency is only used by tests but lives in the main go.mod requirements",
            );
            break;
        }
    }
}

pub(crate) fn detect_bp_61_indirect_dependency_missing_annotation(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    let imports = collect_project_imports(go_mod.root.as_path());
    for require in parse_requires(&go_mod.text) {
        if require.indirect {
            continue;
        }
        let used_directly = imports.all.iter().any(|import| {
            import == &require.module || import.starts_with(&(require.module.clone() + "/"))
        });
        if !used_directly {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_61_META,
                0,
                "requirement is not directly imported; mark it `// indirect` or remove it",
            );
            break;
        }
    }
}

pub(crate) fn detect_bp_62_dependency_used_in_one_file(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    let requires = parse_requires(&go_mod.text);
    let usage = collect_project_module_usage(go_mod.root.as_path(), &requires);
    if usage.non_test_file_count < 2 {
        return;
    }
    for require in requires {
        if require.indirect {
            continue;
        }
        let Some(files) = usage.by_module.get(&require.module) else {
            continue;
        };
        if files.len() == 1 {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_62_META,
                0,
                "external dependency is only used in one non-test file; consider internalizing or narrowing the dependency",
            );
            break;
        }
    }
}

pub(crate) fn detect_bp_63_dependency_with_known_cve_not_updated(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    let advisories = parse_advisories();
    for require in parse_requires(&go_mod.text) {
        let Some(advisory) = advisories.get(&require.module) else {
            continue;
        };
        if advisory.version_matches(&require.version) {
            push_at(
                unit,
                out,
                &crate::lang::go::detectors::bad_practices::BP_63_META,
                0,
                "dependency version matches a curated vulnerable advisory snapshot; upgrade or replace the module",
            );
            break;
        }
    }
}

pub(crate) fn detect_bp_64_replace_directive_local_filesystem(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    if parse_replace_targets(&go_mod.text)
        .into_iter()
        .any(|target| {
            target.starts_with('.') || target.starts_with('/') || target.starts_with("..")
        })
    {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_64_META,
            0,
            "replace directive points at a local filesystem path",
        );
    }
}

pub(crate) fn detect_bp_65_missing_go_sum_entries(
    unit: &ParsedUnit,
    _index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    if is_materialized_fixture(unit) || !is_project_anchor(unit) {
        return;
    }
    let Some(go_mod) = read_go_mod(unit) else {
        return;
    };
    let go_sum = go_mod.root.join("go.sum");
    let missing = !go_sum.is_file()
        || fs::read_to_string(&go_sum)
            .map(|text| text.trim().is_empty())
            .unwrap_or(true);
    if missing {
        push_at(
            unit,
            out,
            &crate::lang::go::detectors::bad_practices::BP_65_META,
            0,
            "go.mod exists but go.sum is missing or empty",
        );
    }
}

#[derive(Clone)]
struct GoModContext {
    root: PathBuf,
    text: String,
}

struct Require {
    module: String,
    version: String,
    indirect: bool,
}

#[derive(Clone)]
struct ProjectImports {
    all: BTreeSet<String>,
    non_test: BTreeSet<String>,
    test_only: BTreeSet<String>,
}

struct ProjectModuleUsage {
    non_test_file_count: usize,
    by_module: BTreeMap<String, BTreeSet<PathBuf>>,
}

struct Advisory {
    introduced_through: Option<String>,
}

fn collect_import_paths(unit: &ParsedUnit) -> Vec<(usize, String)> {
    let mut imports = Vec::new();
    fn walk(node: Node, src: &[u8], imports: &mut Vec<(usize, String)>) {
        if node.kind() == "import_spec"
            && let Some(path) = node.child_by_field_name("path")
            && let Ok(text) = path.utf8_text(src)
        {
            imports.push((
                node.start_byte(),
                text.trim_matches('"').trim_matches('`').to_string(),
            ));
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, src, imports);
        }
    }
    walk(unit.tree.root_node(), unit.source.as_bytes(), &mut imports);
    imports
}

fn read_go_mod(unit: &ParsedUnit) -> Option<GoModContext> {
    use std::sync::{Mutex, OnceLock};
    let root = discover_project_root(&unit.path);
    static CACHE: OnceLock<Mutex<std::collections::HashMap<PathBuf, Option<GoModContext>>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cached) = guard.get(&root) {
        return cached.clone();
    }
    let path = root.join("go.mod");
    let loaded = fs::read_to_string(&path).ok().map(|text| GoModContext {
        root: root.clone(),
        text,
    });
    guard.insert(root, loaded.clone());
    loaded
}

fn parse_requires(go_mod: &str) -> Vec<Require> {
    let mut requires = Vec::new();
    let mut in_block = false;
    for line in go_mod.lines() {
        let trimmed = line.trim();
        if trimmed == "require (" {
            in_block = true;
            continue;
        }
        if in_block && trimmed == ")" {
            in_block = false;
            continue;
        }
        let payload = if in_block {
            trimmed
        } else if let Some(rest) = trimmed.strip_prefix("require ") {
            rest.trim()
        } else {
            continue;
        };
        let mut parts = payload.split_whitespace();
        let Some(module) = parts.next() else { continue };
        let Some(version) = parts.next() else {
            continue;
        };
        let indirect = payload.contains("// indirect");
        requires.push(Require {
            module: module.to_string(),
            version: version.to_string(),
            indirect,
        });
    }
    requires
}

fn parse_go_version(go_mod: &str) -> Option<(u64, u64)> {
    let line = go_mod
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("go "))?;
    let version = line.strip_prefix("go ")?.trim();
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn parse_advisories() -> BTreeMap<String, Advisory> {
    let mut advisories = BTreeMap::new();
    let text = include_str!("../../../../../../ruleset/golang/go_module_advisories.csv");
    for line in text.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split(',');
        let module = parts.next().unwrap_or("").trim();
        let introduced_through = parts.next().map(str::trim).filter(|v| !v.is_empty());
        if module.is_empty() {
            continue;
        }
        advisories.insert(
            module.to_string(),
            Advisory {
                introduced_through: introduced_through.map(|v| v.to_string()),
            },
        );
    }
    advisories
}

fn parse_replace_targets(go_mod: &str) -> Vec<String> {
    let mut targets = Vec::new();
    let mut in_block = false;
    for line in go_mod.lines() {
        let trimmed = line.trim();
        if trimmed == "replace (" {
            in_block = true;
            continue;
        }
        if in_block && trimmed == ")" {
            in_block = false;
            continue;
        }
        let payload = if in_block {
            trimmed
        } else if let Some(rest) = trimmed.strip_prefix("replace ") {
            rest.trim()
        } else {
            continue;
        };
        if let Some((_, target)) = payload.split_once("=>") {
            targets.push(target.split_whitespace().next().unwrap_or("").to_string());
        }
    }
    targets
}

fn version_missing_patch(version: &str) -> bool {
    if !version.starts_with('v') || version.contains('-') {
        return false;
    }
    let numeric = &version[1..];
    let segments: Vec<&str> = numeric.split('.').collect();
    segments.len() < 3
        && segments
            .iter()
            .all(|segment| segment.parse::<u64>().is_ok())
}

fn parse_semver_like(version: &str) -> Option<Vec<u64>> {
    let normalized = version
        .trim()
        .trim_start_matches('v')
        .split_once('+')
        .map_or(version.trim().trim_start_matches('v'), |(head, _)| head)
        .split_once('-')
        .map_or(version.trim().trim_start_matches('v'), |(head, _)| head);
    let mut out = Vec::new();
    for part in normalized.split('.') {
        out.push(part.parse().ok()?);
    }
    Some(out)
}

fn semver_lte(left: &str, right: &str) -> bool {
    let mut left = parse_semver_like(left).unwrap_or_default();
    let mut right = parse_semver_like(right).unwrap_or_default();
    let width = left.len().max(right.len());
    left.resize(width, 0);
    right.resize(width, 0);
    left <= right
}

impl Advisory {
    fn version_matches(&self, version: &str) -> bool {
        let Some(through) = self.introduced_through.as_deref() else {
            return false;
        };
        semver_lte(version, through)
    }
}

fn collect_project_module_usage(root: &Path, requires: &[Require]) -> ProjectModuleUsage {
    let mut non_test_file_count = 0;
    let mut by_module = BTreeMap::<String, BTreeSet<PathBuf>>::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("go")
            || path.to_string_lossy().ends_with("_test.go")
        {
            continue;
        }
        non_test_file_count += 1;
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let imports = extract_imports_from_text(&text);
        for require in requires {
            if imports.iter().any(|import| {
                import == &require.module || import.starts_with(&(require.module.clone() + "/"))
            }) {
                by_module
                    .entry(require.module.clone())
                    .or_default()
                    .insert(path.to_path_buf());
            }
        }
    }
    ProjectModuleUsage {
        non_test_file_count,
        by_module,
    }
}

fn collect_project_imports(root: &Path) -> ProjectImports {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<std::collections::HashMap<PathBuf, ProjectImports>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(cached) = guard.get(root) {
        return cached.clone();
    }

    let mut by_file: BTreeMap<PathBuf, BTreeSet<String>> = BTreeMap::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("go") {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let imports = extract_imports_from_text(&text);
        by_file.insert(path.to_path_buf(), imports);
    }
    let mut all = BTreeSet::new();
    let mut non_test = BTreeSet::new();
    let mut test_only = BTreeSet::new();
    for (path, imports) in by_file {
        let is_test = path.to_string_lossy().ends_with("_test.go");
        for import in imports {
            all.insert(import.clone());
            if is_test {
                test_only.insert(import);
            } else {
                non_test.insert(import);
            }
        }
    }
    test_only.retain(|import| !non_test.contains(import));
    let result = ProjectImports {
        all,
        non_test,
        test_only,
    };
    guard.insert(root.to_path_buf(), result.clone());
    result
}

fn extract_imports_from_text(source: &str) -> BTreeSet<String> {
    let mut imports = BTreeSet::new();
    let mut in_block = false;
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("import (") {
            in_block = true;
            continue;
        }
        if in_block && trimmed == ")" {
            in_block = false;
            continue;
        }
        let import_line = if in_block {
            trimmed
        } else if let Some(rest) = trimmed.strip_prefix("import ") {
            rest.trim()
        } else {
            continue;
        };
        if let Some(start) = import_line.find('"')
            && let Some(end) = import_line[start + 1..].find('"')
        {
            imports.insert(import_line[start + 1..start + 1 + end].to_string());
        }
    }
    imports
}
