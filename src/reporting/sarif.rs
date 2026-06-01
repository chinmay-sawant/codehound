//! SARIF 2.1.0 reporter (minimal).

use std::io::{self, Write};

use anyhow::Result;
use serde::Serialize;

use crate::engine::AnalysisResult;

#[derive(Serialize)]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
struct SarifDriver<'a> {
    name: &'static str,
    rules: Vec<SarifRule<'a>>,
}

#[derive(Serialize)]
struct SarifRule<'a> {
    id: &'a str,
    name: &'a str,
    short_description: SarifText<'a>,
}

#[derive(Serialize)]
struct SarifText<'a> {
    text: &'a str,
}

#[derive(Serialize)]
struct SarifResult<'a> {
    rule_id: &'a str,
    level: &'static str,
    message: SarifText<'a>,
    locations: Vec<SarifLocation<'a>>,
}

#[derive(Serialize)]
struct SarifLocation<'a> {
    physical_location: SarifPhysicalLocation<'a>,
}

#[derive(Serialize)]
struct SarifPhysicalLocation<'a> {
    artifact_location: SarifArtifactLocation<'a>,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation<'a> {
    uri: &'a str,
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
        if seen_rules.insert(f.rule_id) {
            rules.push(SarifRule {
                id: f.rule_id,
                name: f.rule_title,
                short_description: SarifText { text: f.message.as_str() },
            });
        }
        results.push(SarifResult {
            rule_id: f.rule_id,
            level: match f.severity {
                crate::rules::Severity::Info => "note",
                crate::rules::Severity::Warning => "warning",
                crate::rules::Severity::High | crate::rules::Severity::Critical => "error",
            },
            message: SarifText {
                text: f.message.as_str(),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: f.file.as_str(),
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

    let stdout = io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, &log)?;
    out.write_all(b"\n")?;
    Ok(())
}
