use std::collections::HashMap;
use std::sync::OnceLock;

use codehound::cli::RuleCategory;
use codehound::cwe::{RuleDescription, default_ruleset_path, load_rule_descriptions};
use codehound::engine::Registry;
use codehound::rules::{RuleExplainability, category_for_rule_id};

pub(crate) fn print_rules(category: Option<RuleCategory>) {
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
            let maturity = RuleExplainability::for_rule(id).maturity;
            println!("  {id:<12} [{maturity}] {title}");
        }
    }
    if descriptions.is_empty() {
        eprintln!(
            "(rule descriptions not loaded from {}; install or build with ruleset)",
            default_ruleset_path().display()
        );
    }
}

pub(crate) fn print_rule_explanation(rule_id: &str) {
    let registry = Registry::default();
    for det in registry.detectors() {
        if det.rule_ids().contains(&rule_id) {
            let Some(m) = det.metadata_for(rule_id) else {
                continue;
            };
            println!("{} — {}", m.id, m.title);
            println!();
            println!("{}", m.description);
            println!();
            // Maturity-backed explainability surface (plan §4.2 / #118).
            // Reuses rules::maturity — no second status model.
            println!("{}", RuleExplainability::for_rule(rule_id).format_block());
            println!();
            println!("Analysis mode: {}", analysis_mode_for(rule_id));
            println!("Confidence: {}", confidence_for(rule_id));
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

/// High-level analysis mode for `--explain` (taint vs structural vs style).
fn analysis_mode_for(rule_id: &str) -> &'static str {
    match rule_id {
        "CWE-22" | "CWE-78" | "CWE-79" | "CWE-89" | "CWE-90" | "CWE-91" => {
            "taint (enable with --taint / --profile security)"
        }
        id if id.starts_with("BP-") => "style / bad-practice heuristic",
        id if id.starts_with("PERF-") => "structural / hot-path heuristic",
        id if id.starts_with("CWE-") => "structural CWE heuristic (needle + AST facts)",
        _ => "heuristic",
    }
}

fn confidence_for(rule_id: &str) -> &'static str {
    use codehound::rules::{RuleMaturity, maturity_for};
    match maturity_for(rule_id) {
        RuleMaturity::TaintCore => "medium–high when taint is on (graph reachability)",
        RuleMaturity::Structural => "medium (AST / structural patterns)",
        RuleMaturity::Heuristic => "low–medium (heuristic; may FP)",
        RuleMaturity::FixtureOnly => "fixture-only (not for production CI packs)",
        RuleMaturity::Reserved => "reserved / incomplete (not for production CI packs)",
    }
}

fn load_descriptions() -> &'static HashMap<String, RuleDescription> {
    static CACHE: OnceLock<HashMap<String, RuleDescription>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let path = default_ruleset_path();
        match load_rule_descriptions(&path) {
            Ok(map) => map,
            Err(e) => {
                tracing::warn!(
                    "could not load rule descriptions from {}: {e}",
                    path.display()
                );
                HashMap::new()
            }
        }
    })
}
