//! SARIF 2.1.0 reporter.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::SystemTime;

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use crate::engine::AnalysisResult;

const SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_VERSION: &str = "2.1.0";
const TOOL_NAME: &str = "slopguard";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const TOOL_URI: &str = env!("CARGO_PKG_REPOSITORY");

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub version: &'static str,
    pub runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifRun<'a> {
    pub tool: SarifTool<'a>,
    pub invocations: Vec<SarifInvocation<'a>>,
    pub results: Vec<SarifResult<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifRunProperties<'a>>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifRunProperties<'a> {
    #[serde(rename = "slopguardScanStats", skip_serializing_if = "Option::is_none")]
    pub scan_stats: Option<&'a crate::engine::ScanStats>,
    #[serde(rename = "slopguardTiming", skip_serializing_if = "Option::is_none")]
    pub timing: Option<&'a crate::engine::TimingSummary>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifTool<'a> {
    pub driver: SarifDriver<'a>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifDriver<'a> {
    pub name: &'static str,
    #[serde(rename = "informationUri")]
    pub information_uri: &'static str,
    pub version: &'static str,
    #[serde(rename = "semanticVersion")]
    pub semantic_version: &'static str,
    pub rules: Vec<SarifRule<'a>>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifRule<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub short_description: SarifText<'a>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifText<'a> {
    pub text: &'a str,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifResult<'a> {
    #[serde(rename = "ruleId")]
    pub rule_id: &'a str,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: &'static str,
    pub message: SarifText<'a>,
    pub locations: Vec<SarifLocation<'a>>,
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: BTreeMap<&'static str, String>,
    /// SARIF `rank` is 0.0-100.0; our `confidence` is 0.0-1.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressions: Option<Vec<SarifSuppression>>,
    pub properties: SarifProperties,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifSuppression {
    pub kind: &'static str,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifProperties {
    pub tags: Vec<String>,
    #[serde(rename = "security-severity")]
    pub security_severity: &'static str,
    #[serde(rename = "slopguardEvidence", skip_serializing_if = "Option::is_none")]
    pub slopguard_evidence: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifLocation<'a> {
    pub physical_location: SarifPhysicalLocation<'a>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifPhysicalLocation<'a> {
    pub artifact_location: SarifArtifactLocation<'a>,
    pub region: SarifRegion,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifArtifactLocation<'a> {
    pub uri: &'a str,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifRegion {
    pub start_line: usize,
    pub start_column: usize,
    #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    #[serde(rename = "byteOffset", skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<usize>,
    #[serde(rename = "byteLength", skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<usize>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifInvocation<'a> {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    #[serde(rename = "endTimeUtc")]
    pub end_time_utc: String,
    #[serde(rename = "workingDirectory")]
    pub working_directory: SarifArtifactLocation<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<SarifInvocationProperties>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifInvocationProperties {
    #[serde(rename = "suppressedFindings")]
    pub suppressed_findings: usize,
}

pub fn print(result: &AnalysisResult) -> Result<()> {
    print_with(result, true)
}

pub fn print_compact(result: &AnalysisResult) -> Result<()> {
    print_with(result, false)
}

fn print_with(result: &AnalysisResult, pretty: bool) -> Result<()> {
    let log = build_log(result);
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

fn build_log(result: &AnalysisResult) -> SarifLog<'_> {
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

    let rule_index_of: std::collections::HashMap<&str, usize> =
        rules.iter().enumerate().map(|(i, r)| (r.id, i)).collect();

    let results: Vec<SarifResult> = result
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                crate::rules::Severity::Info => "note",
                crate::rules::Severity::Low => "warning",
                crate::rules::Severity::Medium => "warning",
                crate::rules::Severity::High | crate::rules::Severity::Critical => "error",
            };
            let severity_score = match f.severity {
                crate::rules::Severity::Info => "0.0",
                crate::rules::Severity::Low => "2.0",
                crate::rules::Severity::Medium => "5.0",
                crate::rules::Severity::High => "7.5",
                crate::rules::Severity::Critical => "9.5",
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
            if let Some(extra_tags) = f.tags.as_deref() {
                for tag in extra_tags {
                    if !tags.contains(tag) {
                        tags.push(tag.clone());
                    }
                }
            }
            let mut partial_fingerprints: BTreeMap<&'static str, String> = BTreeMap::new();
            partial_fingerprints.insert("slopguard/v1", f.fingerprint_string());

            let slopguard_evidence = f
                .evidence
                .as_ref()
                .and_then(|ev| serde_json::to_value(ev).ok());

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
                            end_line: f.end_line,
                            end_column: f.end_column,
                            byte_offset: f.byte_offset,
                            byte_length: f.byte_length,
                        },
                    },
                }],
                partial_fingerprints,
                rank: f.confidence.map(|c| (c as f64) * 100.0),
                suppressions: f
                    .suppressed
                    .then(|| vec![SarifSuppression { kind: "external" }]),
                properties: SarifProperties {
                    tags,
                    security_severity: severity_score,
                    slopguard_evidence,
                    remediation: f.remediation.clone(),
                },
            }
        })
        .collect();

    let invocation = SarifInvocation {
        execution_successful: result.errors.is_empty(),
        end_time_utc: iso8601_utc_now(),
        working_directory: SarifArtifactLocation { uri: "." },
        properties: (result.suppressed_count > 0).then_some(SarifInvocationProperties {
            suppressed_findings: result.suppressed_count,
        }),
    };

    let run_properties = result.stats.as_ref().map(|stats| SarifRunProperties {
        scan_stats: Some(stats),
        timing: stats.timing.as_ref(),
    });

    SarifLog {
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
            properties: run_properties,
        }],
    }
}

fn iso8601_utc_now() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let (year, month, day, hour, minute, second) = unix_epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
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
    (
        y as u32,
        m as u32,
        d as u32,
        hour as u32,
        minute as u32,
        second as u32,
    )
}

#[doc(hidden)]
pub fn render_to_string(result: &AnalysisResult) -> String {
    let log = build_log(result);
    let mut buf = Vec::new();
    serde_json::to_writer_pretty(&mut buf, &log).unwrap();
    String::from_utf8(buf).unwrap()
}
