//! SARIF 2.1.0 reporter.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::SystemTime;

use anyhow::Result;
use serde::Serialize;

use crate::engine::AnalysisResult;

const SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "slopguard";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const TOOL_URI: &str = env!("CARGO_PKG_REPOSITORY");

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
    invocations: Vec<SarifInvocation<'a>>,
    results: Vec<SarifResult<'a>>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: SarifDriver<'a>,
}

#[derive(Serialize)]
struct SarifDriver<'a> {
    name: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    version: &'static str,
    #[serde(rename = "semanticVersion")]
    semantic_version: &'static str,
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
    #[serde(rename = "ruleId")]
    rule_id: &'a str,
    #[serde(rename = "ruleIndex")]
    rule_index: usize,
    level: &'static str,
    message: SarifText<'a>,
    locations: Vec<SarifLocation<'a>>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: BTreeMap<&'static str, String>,
    properties: SarifProperties,
}

#[derive(Serialize)]
struct SarifProperties {
    tags: Vec<String>,
    #[serde(rename = "security-severity")]
    security_severity: &'static str,
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

#[derive(Serialize)]
struct SarifInvocation<'a> {
    #[serde(rename = "executionSuccessful")]
    execution_successful: bool,
    #[serde(rename = "endTimeUtc")]
    end_time_utc: String,
    #[serde(rename = "workingDirectory")]
    working_directory: SarifArtifactLocation<'a>,
}

pub fn print(result: &AnalysisResult) -> Result<()> {
    print_with(result, true)
}

pub fn print_compact(result: &AnalysisResult) -> Result<()> {
    print_with(result, false)
}

fn print_with(result: &AnalysisResult, pretty: bool) -> Result<()> {
    // 1. Collect unique rules, sorted alphabetically for deterministic output.
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for f in &result.findings {
        seen.entry(f.rule_id).or_insert(f.rule_title);
    }
    let rules: Vec<SarifRule> = seen
        .iter()
        .map(|(id, name)| SarifRule {
            id,
            name,
            short_description: SarifText { text: name },
        })
        .collect();

    // 2. Map rule_id → index in `rules` for ruleIndex.
    let rule_index_of: std::collections::HashMap<&str, usize> = rules
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id, i))
        .collect();

    // 3. Build results.
    let results: Vec<SarifResult> = result
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                crate::rules::Severity::Info => "note",
                crate::rules::Severity::Warning => "warning",
                crate::rules::Severity::High | crate::rules::Severity::Critical => "error",
            };
            let severity_score = match f.severity {
                crate::rules::Severity::Info => "0.0",
                crate::rules::Severity::Warning => "4.0",
                crate::rules::Severity::High => "7.0",
                crate::rules::Severity::Critical => "9.0",
            };
            let mut tags: Vec<String> = vec!["security".to_string()];
            if f.rule_id.starts_with("CWE-") {
                tags.push("cwe".to_string());
            }
            if let Some(cwes) = f.cwe.as_deref() {
                for c in cwes {
                    tags.push(format!("cwe-{}", c.id));
                }
            }
            let mut partial_fingerprints: BTreeMap<&'static str, String> = BTreeMap::new();
            let fingerprint = format!(
                "{}:{}:{}:{}:{}",
                env!("CARGO_PKG_VERSION"),
                f.rule_id,
                f.file,
                f.line,
                f.column,
            );
            partial_fingerprints.insert("slopguard/v1", fingerprint);

            SarifResult {
                rule_id: f.rule_id,
                rule_index: *rule_index_of
                    .get(f.rule_id)
                    .expect("rule_id present in rule_index_of"),
                level,
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
                partial_fingerprints,
                properties: SarifProperties {
                    tags,
                    security_severity: severity_score,
                },
            }
        })
        .collect();

    // 4. Invocation block.
    let invocation = SarifInvocation {
        execution_successful: result.errors.is_empty(),
        end_time_utc: iso8601_utc_now(),
        working_directory: SarifArtifactLocation { uri: "." },
    };

    let log = SarifLog {
        schema: SCHEMA_URL,
        version: SARIF_VERSION,
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: TOOL_NAME,
                    information_uri: TOOL_URI,
                    version: TOOL_VERSION,
                    semantic_version: TOOL_VERSION,
                    rules,
                },
            },
            invocations: vec![invocation],
            results,
        }],
    };

    let stdout = io::stdout();
    let mut out = stdout.lock();
    if pretty {
        serde_json::to_writer_pretty(&mut out, &log)?;
    } else {
        serde_json::to_writer(&mut out, &log)?;
    }
    out.write_all(b"\n")?;
    Ok(())
}

fn iso8601_utc_now() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let (year, month, day, hour, minute, second) = unix_epoch_to_ymdhms(secs);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    )
}

fn unix_epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Howard Hinnant's civil_from_days (public domain).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32, hour as u32, minute as u32, second as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Finding, LineCol, Severity};
    use std::borrow::Cow;

    fn sample_result() -> AnalysisResult {
        AnalysisResult {
            findings: vec![
                Finding::new(
                    "CWE-22",
                    "Path traversal",
                    "a.go",
                    LineCol { line: 1, column: 1 },
                    "msg",
                    Severity::High,
                    Cow::Borrowed(&[]),
                ),
                Finding::new(
                    "CWE-89",
                    "SQL injection",
                    "b.go",
                    LineCol { line: 2, column: 3 },
                    "msg2",
                    Severity::Critical,
                    Cow::Borrowed(&[]),
                ),
            ],
            errors: vec![],
        }
    }

    fn render_to_string(result: &AnalysisResult) -> String {
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for f in &result.findings {
            seen.entry(f.rule_id).or_insert(f.rule_title);
        }
        let rules: Vec<SarifRule> = seen
            .iter()
            .map(|(id, name)| SarifRule {
                id,
                name,
                short_description: SarifText { text: name },
            })
            .collect();
        let rule_index_of: std::collections::HashMap<&str, usize> = rules
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id, i))
            .collect();
        let results: Vec<SarifResult> = result
            .findings
            .iter()
            .map(|f| SarifResult {
                rule_id: f.rule_id,
                rule_index: rule_index_of.get(f.rule_id).copied().unwrap_or(0),
                level: "warning",
                message: SarifText { text: f.message.as_str() },
                locations: vec![],
                partial_fingerprints: BTreeMap::new(),
                properties: SarifProperties {
                    tags: vec!["security".to_string()],
                    security_severity: "5.0",
                },
            })
            .collect();
        let log = SarifLog {
            schema: SCHEMA_URL,
            version: SARIF_VERSION,
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: TOOL_NAME,
                        information_uri: TOOL_URI,
                        version: TOOL_VERSION,
                        semantic_version: TOOL_VERSION,
                        rules,
                    },
                },
                invocations: vec![SarifInvocation {
                    execution_successful: true,
                    end_time_utc: "1970-01-01T00:00:00Z".to_string(),
                    working_directory: SarifArtifactLocation { uri: "." },
                }],
                results,
            }],
        };
        serde_json::to_string_pretty(&log).unwrap()
    }

    #[test]
    fn driver_fields_are_populated() {
        let log = render_to_string(&sample_result());
        assert!(log.contains("\"informationUri\""), "got: {log}");
        assert!(log.contains("\"semanticVersion\""), "got: {log}");
        assert!(log.contains("\"name\": \"slopguard\""), "got: {log}");
    }

    #[test]
    fn rules_array_is_sorted_alphabetically() {
        let log = render_to_string(&sample_result());
        let i22 = log.find("\"CWE-22\"").expect("CWE-22");
        let i89 = log.find("\"CWE-89\"").expect("CWE-89");
        assert!(i22 < i89, "CWE-22 should appear before CWE-89, got: {log}");
    }

    #[test]
    fn results_have_rule_index_pointing_into_rules() {
        let log = render_to_string(&sample_result());
        assert!(log.contains("\"ruleIndex\""), "got: {log}");
    }

    #[test]
    fn results_have_partial_fingerprints() {
        let log = render_to_string(&sample_result());
        assert!(
            log.contains("\"partialFingerprints\""),
            "missing partialFingerprints, got: {log}"
        );
    }

    #[test]
    fn results_have_security_severity_in_properties() {
        let log = render_to_string(&sample_result());
        assert!(log.contains("\"security-severity\""), "got: {log}");
        assert!(log.contains("\"tags\""), "got: {log}");
    }

    #[test]
    fn invocations_block_present() {
        let log = render_to_string(&sample_result());
        assert!(log.contains("\"invocations\""), "got: {log}");
        assert!(log.contains("\"endTimeUtc\""), "got: {log}");
    }

    #[test]
    fn iso8601_format_is_correct() {
        // 2024-01-01T00:00:00Z = 1704067200
        let s = iso8601_from_secs(1_704_067_200);
        assert_eq!(s, "2024-01-01T00:00:00Z");
    }

    fn iso8601_from_secs(secs: u64) -> String {
        let (y, mo, d, h, mi, s) = unix_epoch_to_ymdhms(secs);
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }
}
