use std::collections::HashMap;
use std::sync::OnceLock;

use slopguard::cli::RuleCategory;
use slopguard::cwe::{RuleDescription, default_ruleset_path, load_rule_descriptions};
use slopguard::engine::Registry;
use slopguard::rules::category_for_rule_id;

pub fn print_rules(category: Option<RuleCategory>) {
    let registry = Registry::default();
    let descriptions = load_descriptions();
    let matching_rule_count: usize = registry
        .detectors()
        .iter()
        .flat_map(|d| d.rule_ids().iter())
        .filter(|id| category.is_none_or(|cat| category_for_rule_id(id) == cat.as_category()))
        .count();
    println!(
        "Registered rules ({} detectors, {} rules{}):",
        registry.detector_count(),
        matching_rule_count,
        category
            .map(|cat| format!(", category: {}", cat.as_category()))
            .unwrap_or_default(),
    );
    for det in registry.detectors() {
        for id in det.rule_ids() {
            if category.is_some_and(|cat| category_for_rule_id(id) != cat.as_category()) {
                continue;
            }
            let title = descriptions
                .get(*id)
                .map(|d| d.name.as_str())
                .or_else(|| det.metadata_for(id).map(|m| m.title))
                .unwrap_or("<missing metadata>");
            println!("  {id:<12} {title}");
        }
    }
    if descriptions.is_empty() {
        eprintln!(
            "(rule descriptions not loaded from {}; install or build with ruleset)",
            default_ruleset_path().display()
        );
    }
}

pub fn print_rule_explanation(rule_id: &str) {
    let registry = Registry::default();
    for det in registry.detectors() {
        if det.rule_ids().contains(&rule_id) {
            let Some(m) = det.metadata_for(rule_id) else {
                continue;
            };
            println!("{} — {}", m.id, m.title);
            println!();
            println!("{}", m.description);
            if let Some(fix) = m.fix {
                println!();
                println!("Fix: {fix}");
            }
            let descriptions = load_descriptions();
            if let Some(rich) = descriptions.get(rule_id) {
                if rich.description != m.description {
                    println!();
                    println!("From the CWE catalog:");
                    println!("{}", rich.description);
                }
                if !rich.detection_notes.is_empty() {
                    println!();
                    println!("Detection notes:");
                    println!("{}", rich.detection_notes);
                }
            }
            return;
        }
    }
    eprintln!("unknown rule: {rule_id}");
}

fn load_descriptions() -> &'static HashMap<String, RuleDescription> {
    static CACHE: OnceLock<HashMap<String, RuleDescription>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let path = default_ruleset_path();
        match load_rule_descriptions(&path) {
            Ok(map) => map,
            Err(e) => {
                eprintln!(
                    "warning: could not load rule descriptions from {}: {e}",
                    path.display()
                );
                HashMap::new()
            }
        }
    })
}
