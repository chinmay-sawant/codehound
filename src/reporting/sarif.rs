//! SARIF 2.1.0 reporter (minimal).

use anyhow::Result;
use serde::Serialize;

use crate::engine::AnalysisResult;

#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Serialize)]
struct SarifRule {
    id: String,
    name: String,
    short_description: SarifText,
}

#[derive(Serialize)]
struct SarifText {
    text: String,
}

#[derive(Serialize)]
struct SarifResult {
    rule_id: String,
    level: String,
    message: SarifText,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifRegion {
    start_line: usize,
    start_column: usize,
}

pub fn print(result: &AnalysisResult) -> Result<()> {
    let mut rules = Vec::new();
    let mut results = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    for f in &result.findings {
        if seen_rules.insert(f.rule_id.to_string()) {
            rules.push(SarifRule {
                id: f.rule_id.to_string(),
                name: f.rule_title.to_string(),
                short_description: SarifText {
                    text: f.message.clone(),
                },
            });
        }
        results.push(SarifResult {
            rule_id: f.rule_id.to_string(),
            level: match f.severity {
                crate::rules::Severity::Info => "note",
                crate::rules::Severity::Warning => "warning",
                crate::rules::Severity::High | crate::rules::Severity::Critical => "error",
            }
            .to_string(),
            message: SarifText {
                text: f.message.clone(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.file.clone(),
                    },
                    region: SarifRegion {
                        start_line: f.line,
                        start_column: f.column,
                    },
                },
            }],
        });
    }

    let log = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "slopguard",
                    rules,
                },
            },
            results,
        }],
    };

    println!("{}", serde_json::to_string_pretty(&log)?);
    Ok(())
}
