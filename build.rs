#[path = "build/types.rs"]
mod types;
#[path = "build/parse.rs"]
mod parse;
#[path = "build/escape.rs"]
mod escape;
#[path = "build/gen_catalogue.rs"]
mod gen_catalogue;
#[path = "build/gen_cwe.rs"]
mod gen_cwe;
#[path = "build/gen_perf.rs"]
mod gen_perf;

use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

use types::{PerfRegistryFile, RegistryFile};

fn read_registry_entries(dir_or_file: &str) -> Vec<types::RegistryDetector> {
    let path = Path::new(dir_or_file);
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().map_or(false, |e| e == "toml") {
                let text = fs::read_to_string(entry.path()).unwrap();
                let reg: RegistryFile = toml::from_str(&text).unwrap();
                entries.extend(reg.detector);
            }
        }
    } else if path.is_file() {
        let text = fs::read_to_string(path).unwrap();
        let reg: RegistryFile = toml::from_str(&text).unwrap();
        entries = reg.detector;
    }
    entries
}

fn read_perf_registry_entries(dir_or_file: &str) -> Vec<types::PerfRegistryDetector> {
    let path = Path::new(dir_or_file);
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.path().extension().map_or(false, |e| e == "toml") {
                let text = fs::read_to_string(entry.path()).unwrap();
                let reg: PerfRegistryFile = toml::from_str(&text).unwrap();
                entries.extend(reg.detector);
            }
        }
    } else if path.is_file() {
        let text = fs::read_to_string(path).unwrap();
        let reg: PerfRegistryFile = toml::from_str(&text).unwrap();
        entries = reg.detector;
    }
    entries
}

fn main() {
    let json_path = PathBuf::from("ruleset/golang/golang.json");
    println!("cargo:rerun-if-changed={}", json_path.display());
    println!("cargo:rerun-if-changed=src/lang/go/detectors/cwe/registry");
    println!("cargo:rerun-if-changed=src/lang/go/detectors/cwe/domains");
    println!("cargo:rerun-if-changed=src/lang/go/detectors/perf/registry");
    println!("cargo:rerun-if-changed=src/lang/go/detectors/perf/domains");

    let parsed: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&json_path).expect("Failed to read ruleset/golang/golang.json"),
    )
    .expect("Failed to parse ruleset/golang/golang.json as JSON");

    let cwe_registry_entries =
        read_registry_entries("src/lang/go/detectors/cwe/registry");
    let perf_registry_entries =
        read_perf_registry_entries("src/lang/go/detectors/perf/registry");

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
    let perf_registry_out = out_dir.join("go_perf_registry.rs");

    let rules = parse::parse_rules(&parsed);
    let cwe_rule_map = parse::build_cwe_rule_map(&rules);
    let perf_rule_map = parse::build_perf_rule_map(&rules);

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
        &perf_registry_out,
        gen_perf::generate_go_perf_registry_code(&perf_registry_entries),
    )
    .expect("Failed to write go_perf_registry.rs");
}
