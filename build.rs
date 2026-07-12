#[path = "build/escape.rs"]
mod escape;
#[path = "build/gen_bp.rs"]
mod gen_bp;
#[path = "build/gen_catalogue.rs"]
mod gen_catalogue;
#[path = "build/gen_cwe.rs"]
mod gen_cwe;
#[path = "build/gen_metadata.rs"]
mod gen_metadata;
#[path = "build/gen_perf.rs"]
mod gen_perf;
#[path = "build/parse.rs"]
mod parse;
#[path = "build/types.rs"]
mod types;

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use types::{PerfRegistryFile, RegistryFile};

fn read_ruleset_value(path: &Path) -> serde_json::Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read ruleset chunk {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!(
            "Failed to parse ruleset chunk {} as JSON: {e}",
            path.display()
        )
    })
}

fn read_ruleset_chunks(dir: &Path) -> serde_json::Value {
    let mut merged = serde_json::Map::new();
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read ruleset chunk dir {}: {e}", dir.display()))
        .map(|entry| entry.unwrap_or_else(|e| panic!("read entry in {}: {e}", dir.display())))
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let value = read_ruleset_value(&path);
        let obj = value
            .as_object()
            .unwrap_or_else(|| panic!("ruleset chunk {} must be a JSON object", path.display()));
        for (key, value) in obj {
            if merged.insert(key.clone(), value.clone()).is_some() {
                panic!("duplicate rule id {key} across ruleset chunks");
            }
        }
    }

    serde_json::Value::Object(merged)
}

fn read_registry_entries(dir_or_file: &str) -> Vec<types::RegistryDetector> {
    let path = Path::new(dir_or_file);
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(path)
            .unwrap_or_else(|e| panic!("read CWE registry dir {dir_or_file}: {e}"))
        {
            let entry =
                entry.unwrap_or_else(|e| panic!("read CWE registry entry in {dir_or_file}: {e}"));
            if entry.path().extension().is_some_and(|e| e == "toml") {
                let entry_path = entry.path();
                let text = fs::read_to_string(&entry_path).unwrap_or_else(|e| {
                    panic!("read CWE registry file {}: {e}", entry_path.display())
                });
                let reg: RegistryFile = toml::from_str(&text).unwrap_or_else(|e| {
                    panic!("parse CWE registry TOML {}: {e}", entry_path.display())
                });
                entries.extend(reg.detector);
            }
        }
    } else if path.is_file() {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read CWE registry file {dir_or_file}: {e}"));
        let reg: RegistryFile = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("parse CWE registry TOML {dir_or_file}: {e}"));
        entries = reg.detector;
    }
    for d in &entries {
        d.validate();
    }
    entries
}

fn read_perf_registry_entries(dir_or_file: &str) -> Vec<types::PerfRegistryDetector> {
    let path = Path::new(dir_or_file);
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(path)
            .unwrap_or_else(|e| panic!("read PERF registry dir {dir_or_file}: {e}"))
        {
            let entry =
                entry.unwrap_or_else(|e| panic!("read PERF registry entry in {dir_or_file}: {e}"));
            if entry.path().extension().is_some_and(|e| e == "toml") {
                let entry_path = entry.path();
                let text = fs::read_to_string(&entry_path).unwrap_or_else(|e| {
                    panic!("read PERF registry file {}: {e}", entry_path.display())
                });
                let reg: PerfRegistryFile = toml::from_str(&text).unwrap_or_else(|e| {
                    panic!("parse PERF registry TOML {}: {e}", entry_path.display())
                });
                entries.extend(reg.detector);
            }
        }
    } else if path.is_file() {
        let text = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read PERF registry file {dir_or_file}: {e}"));
        let reg: PerfRegistryFile = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("parse PERF registry TOML {dir_or_file}: {e}"));
        entries = reg.detector;
    }
    for d in &entries {
        d.validate();
    }
    entries
}

fn main() {
    let chunk_dir = PathBuf::from("ruleset/golang/chunks");
    let bad_practices_path = PathBuf::from("ruleset/golang/bad-practices.json");
    println!("cargo:rerun-if-changed={}", chunk_dir.display());
    println!("cargo:rerun-if-changed={}", bad_practices_path.display());
    println!("cargo:rerun-if-changed=src/lang/go/detectors/cwe/registry");
    println!("cargo:rerun-if-changed=src/lang/go/detectors/cwe/domains");
    println!("cargo:rerun-if-changed=src/lang/go/detectors/perf/registry");
    println!("cargo:rerun-if-changed=src/lang/go/detectors/perf/domains");

    let parsed = read_ruleset_chunks(&chunk_dir);
    let bp_parsed = read_ruleset_value(&bad_practices_path);

    let cwe_registry_entries = read_registry_entries("src/lang/go/detectors/cwe/registry");
    let perf_registry_entries = read_perf_registry_entries("src/lang/go/detectors/perf/registry");

    let mut supported_ids = Vec::new();
    for entry in &cwe_registry_entries {
        supported_ids.push(entry.cwe);
    }
    supported_ids.sort_unstable();
    supported_ids.dedup();
    assert_eq!(
        supported_ids.len(),
        cwe_registry_entries.len(),
        "duplicate CWE ids in registry.toml"
    );

    let mut perf_ids = Vec::new();
    for entry in &perf_registry_entries {
        perf_ids.push(entry.perf);
    }
    perf_ids.sort_unstable();
    perf_ids.dedup();
    assert_eq!(
        perf_ids.len(),
        perf_registry_entries.len(),
        "duplicate PERF ids in registry.toml"
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let catalogue_path = out_dir.join("rule_catalogue.rs");
    let cwe_metadata_path = out_dir.join("go_cwe_metadata.rs");
    let cwe_catalog_out = out_dir.join("cwe_catalog_generated.rs");
    let cwe_registry_out = out_dir.join("go_cwe_registry.rs");
    let perf_metadata_path = out_dir.join("go_perf_metadata.rs");
    let bp_metadata_path = out_dir.join("go_bp_metadata.rs");
    let perf_registry_out = out_dir.join("go_perf_registry.rs");

    let rules = parse::parse_rules(&parsed);
    let bp_rules = parse::parse_rules(&bp_parsed);
    let cwe_rule_map = parse::build_cwe_rule_map(&rules);
    let perf_rule_map = parse::build_perf_rule_map(&rules);
    let bp_rule_map = parse::build_bp_rule_map(&bp_rules);
    let mut bp_ids: Vec<u32> = bp_rule_map.keys().copied().collect();
    bp_ids.sort_unstable();

    fs::write(
        &catalogue_path,
        gen_catalogue::generate_rule_catalogue_code(&rules),
    )
    .expect("Failed to write rule_catalogue.rs");
    fs::write(
        &cwe_metadata_path,
        gen_cwe::generate_go_metadata_code(&cwe_rule_map, &supported_ids),
    )
    .expect("Failed to write go_cwe_metadata.rs");
    fs::write(
        &cwe_registry_out,
        gen_cwe::generate_go_registry_code(&cwe_registry_entries),
    )
    .expect("Failed to write go_cwe_registry.rs");
    fs::write(
        &cwe_catalog_out,
        gen_cwe::generate_cwe_catalog_code(&cwe_rule_map),
    )
    .expect("Failed to write cwe_catalog_generated.rs");
    fs::write(
        &perf_metadata_path,
        gen_perf::generate_go_perf_metadata_code(&perf_rule_map, &perf_ids),
    )
    .expect("Failed to write go_perf_metadata.rs");
    fs::write(
        &bp_metadata_path,
        gen_bp::generate_go_bp_metadata_code(&bp_rule_map, &bp_ids),
    )
    .expect("Failed to write go_bp_metadata.rs");
    fs::write(
        &perf_registry_out,
        gen_perf::generate_go_perf_registry_code(&perf_registry_entries),
    )
    .expect("Failed to write go_perf_registry.rs");
}
