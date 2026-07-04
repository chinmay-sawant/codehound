//! SARIF log builder: converts an `AnalysisResult` into a `SarifLog`.

use std::collections::BTreeMap;

use crate::engine::AnalysisResult;
use crate::rules::DetectorEvidence;
use crate::rules::category_for_rule_id;

use super::schema::{
    SarifArtifactLocation, SarifInvocation, SarifInvocationProperties, SarifLocation, SarifLog,
    SarifPhysicalLocation, SarifProperties, SarifRegion, SarifResult, SarifRule, SarifRun,
    SarifRunProperties, SarifSuppression, SarifText,
};
use super::time::iso8601_utc_now;

pub(super) fn build_log(result: &AnalysisResult) -> SarifLog<'_> {
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
        .filter_map(|f| {
            let rule_index = *rule_index_of.get(f.rule_id)?;
            let level = match f.severity {
                crate::rules::Severity::Info => "note",
                crate::rules::Severity::Low => "warning",
                crate::rules::Severity::Medium => "warning",
                crate::rules::Severity::High | crate::rules::Severity::Critical => "error",
            };
            let category = category_for_rule_id(f.rule_id);
            let severity_score = if category == "bad_practice" {
                "5.0"
            } else {
                match f.severity {
                    crate::rules::Severity::Info => "0.0",
                    crate::rules::Severity::Low => "2.0",
                    crate::rules::Severity::Medium => "5.0",
                    crate::rules::Severity::High => "7.5",
                    crate::rules::Severity::Critical => "9.5",
                }
            };
            let mut tags: Vec<String> = vec!["security".to_string()];
            if f.rule_id.starts_with("CWE-") {
                tags.push("cwe".to_string());
            } else if f.rule_id.starts_with("PERF-") {
                tags.push("performance".to_string());
            } else if f.rule_id.starts_with("BP-") {
                tags.push("bad_practice".to_string());
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

            Some(SarifResult {
                rule_id: f.rule_id,
                rule_index,
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
                    category,
                    security_severity: severity_score,
                    slopguard_evidence,
                    remediation: f.remediation.clone(),
                    taint_show_paths: matches!(
                        f.evidence.as_ref(),
                        Some(DetectorEvidence::TaintFlow { sink, .. }) if !sink.hop_details.is_empty()
                    )
                    .then_some(true),
                },
            })
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
        schema: super::schema::SCHEMA_URL,
        version: super::schema::SARIF_VERSION,
        runs: vec![SarifRun {
            tool: super::schema::SarifTool {
                driver: super::schema::SarifDriver {
                    name: "slopguard",
                    information_uri: env!("CARGO_PKG_REPOSITORY"),
                    version: env!("CARGO_PKG_VERSION"),
                    semantic_version: env!("CARGO_PKG_VERSION"),
                    rules,
                },
            },
            invocations: vec![invocation],
            results,
            properties: run_properties,
        }],
    }
}
