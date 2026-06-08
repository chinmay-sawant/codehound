use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, serde::Deserialize)]
struct RegistryFile {
    detector: Vec<RegistryDetector>,
}

#[derive(Debug, serde::Deserialize)]
struct RegistryDetector {
    cwe: u32,
    #[allow(dead_code)]
    domain: String,
    function: String,
}

#[derive(Debug, serde::Deserialize)]
struct PerfRegistryFile {
    detector: Vec<PerfRegistryDetector>,
}

#[derive(Debug, serde::Deserialize)]
struct PerfRegistryDetector {
    perf: u32,
    #[allow(dead_code)]
    domain: String,
    function: String,
}

fn main() {
    let json_path = PathBuf::from("ruleset/golang/golang.json");
    let cwe_registry_path = PathBuf::from("src/lang/go/detectors/cwe/registry.toml");
    let perf_registry_path = PathBuf::from("src/lang/go/detectors/perf/registry.toml");

    println!("cargo:rerun-if-changed={}", json_path.display());
    println!("cargo:rerun-if-changed={}", cwe_registry_path.display());
    println!("cargo:rerun-if-changed=src/lang/go/detectors/cwe/domains");
    println!("cargo:rerun-if-changed={}", perf_registry_path.display());
    println!("cargo:rerun-if-changed=src/lang/go/detectors/perf/domains");

    let parsed: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&json_path).expect("Failed to read ruleset/golang/golang.json"),
    )
    .expect("Failed to parse ruleset/golang/golang.json as JSON");

    let cwe_registry_text =
        fs::read_to_string(&cwe_registry_path).expect("Failed to read go CWE registry.toml");
    let cwe_registry: RegistryFile =
        toml::from_str(&cwe_registry_text).expect("Failed to parse go CWE registry.toml");

    let perf_registry_text =
        fs::read_to_string(&perf_registry_path).expect("Failed to read go PERF registry.toml");
    let perf_registry: PerfRegistryFile =
        toml::from_str(&perf_registry_text).expect("Failed to parse go PERF registry.toml");

    let mut supported_ids = Vec::new();
    for entry in &cwe_registry.detector {
        supported_ids.push(entry.cwe);
    }
    supported_ids.sort_unstable();
    supported_ids.dedup();
    assert_eq!(
        supported_ids.len(),
        cwe_registry.detector.len(),
        "duplicate CWE ids in registry.toml"
    );

    let mut perf_ids = Vec::new();
    for entry in &perf_registry.detector {
        perf_ids.push(entry.perf);
    }
    perf_ids.sort_unstable();
    perf_ids.dedup();
    assert_eq!(
        perf_ids.len(),
        perf_registry.detector.len(),
        "duplicate PERF ids in registry.toml"
    );

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let catalogue_path = out_dir.join("rule_catalogue.rs");
    let cwe_metadata_path = out_dir.join("go_cwe_metadata.rs");
    let cwe_catalog_out = out_dir.join("cwe_catalog_generated.rs");
    let cwe_registry_out = out_dir.join("go_cwe_registry.rs");
    let perf_metadata_path = out_dir.join("go_perf_metadata.rs");
    let perf_registry_out = out_dir.join("go_perf_registry.rs");

    let rules = parse_rules(&parsed);
    let cwe_rule_map = build_cwe_rule_map(&rules);
    let perf_rule_map = build_perf_rule_map(&rules);

    fs::write(&catalogue_path, generate_rule_catalogue_code(&rules))
        .expect("Failed to write rule_catalogue.rs");
    fs::write(
        &cwe_metadata_path,
        generate_go_metadata_code(&cwe_rule_map, &supported_ids),
    )
    .expect("Failed to write go_cwe_metadata.rs");
    fs::write(
        &cwe_registry_out,
        generate_go_registry_code(&cwe_registry.detector),
    )
    .expect("Failed to write go_cwe_registry.rs");
    fs::write(
        &cwe_catalog_out,
        generate_cwe_catalog_code(&cwe_rule_map),
    )
    .expect("Failed to write cwe_catalog_generated.rs");
    fs::write(
        &perf_metadata_path,
        generate_go_perf_metadata_code(&perf_rule_map, &perf_ids),
    )
    .expect("Failed to write go_perf_metadata.rs");
    fs::write(
        &perf_registry_out,
        generate_go_perf_registry_code(&perf_registry.detector),
    )
    .expect("Failed to write go_perf_registry.rs");
}

#[derive(Debug, Clone)]
struct JsonRule {
    id: String,
    name: String,
    description: String,
    original_description: String,
    category: String,
    detection_notes: String,
}

fn parse_rules(parsed: &serde_json::Value) -> Vec<JsonRule> {
    let obj = parsed.as_object().expect("JSON root must be an object");
    let mut rules = Vec::new();

    for (key, value) in obj {
        let id = value
            .get("id")
            .and_then(parse_rule_id)
            .unwrap_or_else(|| key.to_string());
        let name = value
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let description = value
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let original_description = value
            .get("original_description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let category = value
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let detection_notes = value
            .get("detection_notes")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        rules.push(JsonRule {
            id,
            name,
            description,
            original_description,
            category,
            detection_notes,
        });
    }

    rules.sort_by(|a, b| a.id.cmp(&b.id));
    rules
}

fn build_cwe_rule_map(rules: &[JsonRule]) -> BTreeMap<u32, JsonRule> {
    rules
        .iter()
        .filter_map(|rule| parse_cwe_number(&rule.id).map(|id| (id, rule.clone())))
        .collect()
}

fn build_perf_rule_map(rules: &[JsonRule]) -> BTreeMap<u32, JsonRule> {
    rules
        .iter()
        .filter_map(|rule| parse_perf_number(&rule.id).map(|id| (id, rule.clone())))
        .collect()
}

fn generate_rule_catalogue_code(rules: &[JsonRule]) -> String {
    let mut code = String::new();
    code.push_str("// This file is auto-generated by build.rs from ruleset/golang/golang.json\n");
    code.push_str("// DO NOT EDIT MANUALLY\n\n");
    code.push_str("use std::sync::LazyLock;\n\n");
    code.push_str(
        "static RULE_CATALOGUE_INNER: LazyLock<Vec<RuleDescription>> = LazyLock::new(|| {\n",
    );
    code.push_str("    vec![\n");

    for rule in rules {
        code.push_str(&format!(
            "        RuleDescription {{\n\
             \x20           id: \"{}\".into(),\n\
             \x20           name: \"{}\".into(),\n\
             \x20           description: \"{}\".into(),\n\
             \x20           original_description: \"{}\".into(),\n\
             \x20           category: \"{}\".into(),\n\
             \x20           detection_notes: \"{}\".into(),\n\
             \x20       }},\n",
            escape_rust_string(&rule.id),
            escape_rust_string(&rule.name),
            escape_rust_string(&rule.description),
            escape_rust_string(&rule.original_description),
            escape_rust_string(&rule.category),
            escape_rust_string(&rule.detection_notes),
        ));
    }

    code.push_str("    ]\n");
    code.push_str("});\n\n");
    code.push_str("/// Returns the built-in rule catalogue, compiled at build time from\n");
    code.push_str("/// `ruleset/golang/golang.json` with zero runtime JSON parsing cost.\n");
    code.push_str("pub fn builtin_rule_catalogue() -> &'static [RuleDescription] {\n");
    code.push_str("    &RULE_CATALOGUE_INNER\n");
    code.push_str("}\n");
    code
}

fn generate_go_metadata_code(rule_map: &BTreeMap<u32, JsonRule>, supported_ids: &[u32]) -> String {
    let mut code = String::new();
    code.push_str("// This file is auto-generated by build.rs from ruleset/golang/golang.json\n");
    code.push_str("// DO NOT EDIT MANUALLY\n\n");

    code.push_str("#[allow(dead_code)]\n");
    code.push_str("pub const GO_CWE_RULE_IDS: &[&str] = &[\n");
    for id in supported_ids {
        code.push_str(&format!("    \"CWE-{id}\",\n"));
    }
    code.push_str("];\n\n");

    for id in supported_ids {
        let rule = rule_map
            .get(id)
            .unwrap_or_else(|| panic!("missing JSON metadata for supported rule CWE-{id}"));
        code.push_str(&format!(
            "pub(super) const META_CWE_{id}: RuleMetadata = emit::rule_meta(\n\
             \x20   \"CWE-{id}\",\n\
             \x20   \"{}\",\n\
             \x20   \"{}\",\n\
             \x20   severity_for({id}),\n\
             \x20   go_cwe_ref_slice!({id}, \"{}\"),\n\
             \x20   fix_for({id}),\n\
             );\n\n",
            escape_rust_string(&rule.name),
            escape_rust_string(&rule.description),
            escape_rust_string(&rule.name),
        ));
    }

    code
}

fn generate_go_registry_code(detectors: &[RegistryDetector]) -> String {
    let mut code = String::new();
    code.push_str(
        "// This file is auto-generated by build.rs from src/lang/go/detectors/cwe/registry.toml\n",
    );
    code.push_str("// DO NOT EDIT MANUALLY\n\n");
    code.push_str("const GO_RULES: &[GoRuleEntry] = &[\n");
    for entry in detectors {
        let id = entry.cwe;
        code.push_str(&format!(
            "    (\"CWE-{id}\", {}, &self::metadata::META_CWE_{id}),\n",
            entry.function
        ));
    }
    code.push_str("];\n");
    code
}

fn escape_rust_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn parse_rule_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn parse_cwe_number(id: &str) -> Option<u32> {
    id.strip_prefix("CWE-").unwrap_or(id).parse::<u32>().ok()
}

fn parse_perf_number(id: &str) -> Option<u32> {
    id.strip_prefix("PERF-").unwrap_or(id).parse::<u32>().ok()
}

fn generate_go_perf_metadata_code(
    rule_map: &BTreeMap<u32, JsonRule>,
    supported_ids: &[u32],
) -> String {
    let mut code = String::new();
    code.push_str("// This file is auto-generated by build.rs from ruleset/golang/golang.json\n");
    code.push_str("// DO NOT EDIT MANUALLY\n\n");

    code.push_str("#[allow(dead_code)]\n");
    code.push_str("pub const GO_PERF_RULE_IDS: &[&str] = &[\n");
    for id in supported_ids {
        code.push_str(&format!("    \"PERF-{id}\",\n"));
    }
    code.push_str("];\n\n");

    for id in supported_ids {
        let rule = rule_map
            .get(id)
            .unwrap_or_else(|| panic!("missing JSON metadata for supported rule PERF-{id}"));
        code.push_str(&format!(
            "pub(super) const META_PERF_{id}: RuleMetadata = emit::rule_meta(\n\
             \x20   \"PERF-{id}\",\n\
             \x20   \"{}\",\n\
             \x20   \"{}\",\n\
             \x20   severity_for({id}),\n\
             \x20   perf_ref_slice!({id}, \"{}\"),\n\
             \x20   fix_for({id}),\n\
             );\n\n",
            escape_rust_string(&rule.name),
            escape_rust_string(&rule.description),
            escape_rust_string(&rule.name),
        ));
    }

    code
}

fn generate_cwe_catalog_code(rule_map: &BTreeMap<u32, JsonRule>) -> String {
    let mut code = String::new();
    code.push_str("// This file is auto-generated by build.rs from ruleset/golang/golang.json\n");
    code.push_str("// DO NOT EDIT MANUALLY\n\n");
    code.push_str("pub static CWE_CATALOG_GENERATED: &[CweRef] = &[\n");
    for (id, rule) in rule_map {
        let url = format!("https://cwe.mitre.org/data/definitions/{id}.html");
        code.push_str(&format!(
            "    CweRef::new({}, \"{}\", \"{}\"),\n",
            id,
            escape_rust_string(&rule.name),
            url,
        ));
    }
    code.push_str("];\n");
    code
}

fn generate_go_perf_registry_code(detectors: &[PerfRegistryDetector]) -> String {
    let mut code = String::new();
    code.push_str(
        "// This file is auto-generated by build.rs from src/lang/go/detectors/perf/registry.toml\n",
    );
    code.push_str("// DO NOT EDIT MANUALLY\n\n");
    code.push_str("const GO_PERF_RULES: &[GoPerfEntry] = &[\n");
    for entry in detectors {
        let id = entry.perf;
        code.push_str(&format!(
            "    (\"PERF-{id}\", {}, &self::metadata::META_PERF_{id}),\n",
            entry.function
        ));
    }
    code.push_str("];\n");
    code
}
