//! SARIF log builder: converts an `AnalysisResult` into a `SarifLog`.

use std::collections::BTreeMap;

use crate::engine::AnalysisResult;
use crate::rules::{FindingView, Severity};

use super::schema::{
    SarifArtifactLocation, SarifInvocation, SarifInvocationProperties, SarifLocation, SarifLog,
    SarifPhysicalLocation, SarifProperties, SarifRegion, SarifResult, SarifRule, SarifRun,
    SarifRunProperties, SarifSuppression, SarifText,
};
use crate::engine::time::iso8601_utc_now;

pub(super) fn build_log(result: &AnalysisResult) -> SarifLog<'_> {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for f in &result.findings {
        let view = FindingView::new(f);
        seen.entry(view.rule_id()).or_insert(view.rule_title());
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
            let view = FindingView::new(f);
            let rule_index = *rule_index_of.get(view.rule_id())?;
            let category = view.category();
            let (level, severity_score) = sarif_severity_fields(view.severity(), category);
            let tags = view.sarif_tags();
            let mut partial_fingerprints: BTreeMap<&'static str, String> = BTreeMap::new();
            partial_fingerprints.insert("slopguard/v1", view.fingerprint());

            let slopguard_evidence = view.evidence().and_then(|ev| serde_json::to_value(ev).ok());

            Some(SarifResult {
                rule_id: view.rule_id(),
                rule_index,
                level,
                message: SarifText {
                    text: view.message(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri: view.file() },
                        region: SarifRegion {
                            start_line: view.line(),
                            start_column: view.column(),
                            end_line: view.end_line(),
                            end_column: view.end_column(),
                            byte_offset: view.byte_offset(),
                            byte_length: view.byte_length(),
                        },
                    },
                }],
                partial_fingerprints,
                rank: view.confidence().map(|c| (c as f64) * 100.0),
                suppressions: view
                    .suppressed()
                    .then(|| vec![SarifSuppression { kind: "external" }]),
                properties: SarifProperties {
                    tags,
                    category,
                    security_severity: severity_score,
                    slopguard_evidence,
                    remediation: view.non_empty_remediation().map(str::to_string),
                    taint_show_paths: view.taint_show_paths(),
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

fn sarif_severity_fields(severity: Severity, category: &str) -> (&'static str, &'static str) {
    let level = match severity {
        Severity::Info => "note",
        Severity::Low => "warning",
        Severity::Medium => "warning",
        Severity::High | Severity::Critical => "error",
    };
    let security_severity = if category == "bad_practice" {
        "5.0"
    } else {
        match severity {
            Severity::Info => "0.0",
            Severity::Low => "2.0",
            Severity::Medium => "5.0",
            Severity::High => "7.5",
            Severity::Critical => "9.5",
        }
    };
    (level, security_severity)
}
