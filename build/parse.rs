use std::collections::BTreeMap;

use crate::types::JsonRule;

fn parse_rule_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

pub fn parse_cwe_number(id: &str) -> Option<u32> {
    id.strip_prefix("CWE-").unwrap_or(id).parse::<u32>().ok()
}

pub fn parse_perf_number(id: &str) -> Option<u32> {
    id.strip_prefix("PERF-").unwrap_or(id).parse::<u32>().ok()
}

pub fn parse_bp_number(id: &str) -> Option<u32> {
    id.strip_prefix("BP-").unwrap_or(id).parse::<u32>().ok()
}

pub fn parse_rules(parsed: &serde_json::Value) -> Vec<JsonRule> {
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
        let severity = value
            .get("severity")
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        rules.push(JsonRule {
            id,
            name,
            description,
            original_description,
            category,
            detection_notes,
            severity,
        });
    }

    rules.sort_by(|a, b| a.id.cmp(&b.id));
    rules
}

pub fn build_cwe_rule_map(rules: &[JsonRule]) -> BTreeMap<u32, JsonRule> {
    rules
        .iter()
        .filter_map(|rule| parse_cwe_number(&rule.id).map(|id| (id, rule.clone())))
        .collect()
}

pub fn build_perf_rule_map(rules: &[JsonRule]) -> BTreeMap<u32, JsonRule> {
    rules
        .iter()
        .filter_map(|rule| parse_perf_number(&rule.id).map(|id| (id, rule.clone())))
        .collect()
}

pub fn build_bp_rule_map(rules: &[JsonRule]) -> BTreeMap<u32, JsonRule> {
    rules
        .iter()
        .filter_map(|rule| parse_bp_number(&rule.id).map(|id| (id, rule.clone())))
        .collect()
}
