//! SARIF log builder: converts an `AnalysisResult` into a `SarifLog`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::Error;
use crate::engine::AnalysisResult;
use crate::rules::{FindingView, Severity};

use super::schema::{
    SarifArtifactLocation, SarifInvocation, SarifInvocationProperties, SarifLocation, SarifLog,
    SarifPhysicalLocation, SarifProperties, SarifRegion, SarifResult, SarifRule, SarifRun,
    SarifRunProperties, SarifSuppression, SarifText,
};
use crate::engine::time::iso8601_utc_now;

pub(super) fn build_log(result: &AnalysisResult) -> Result<SarifLog<'_>, Error> {
    // rule_id → (title, optional help URI from first CWE link on a finding)
    let mut seen: BTreeMap<&str, (&str, Option<&str>)> = BTreeMap::new();
    for f in &result.findings {
        let view = FindingView::new(f);
        seen.entry(view.rule_id()).or_insert_with(|| {
            let help = f.cwe.as_ref().and_then(|c| c.first()).map(|c| c.url);
            (view.rule_title(), help)
        });
    }
    let rules: Vec<SarifRule> = seen
        .iter()
        .map(|(id, (name, help_uri))| SarifRule {
            id,
            name,
            short_description: SarifText { text: name },
            // Prefer a non-empty full description; fall back to the title.
            full_description: Some(SarifText { text: name }),
            help_uri: *help_uri,
        })
        .collect();

    let rule_index_of: std::collections::HashMap<&str, usize> =
        rules.iter().enumerate().map(|(i, r)| (r.id, i)).collect();

    let results: Vec<SarifResult> = result
        .findings
        .iter()
        .map(|f| {
            let view = FindingView::new(f);
            let rule_index =
                *rule_index_of
                    .get(view.rule_id())
                    .ok_or_else(|| Error::SarifRule {
                        rule_id: view.rule_id().to_owned(),
                    })?;
            let category = view.category();
            let (level, severity_score) = sarif_severity_fields(view.severity(), category);
            let tags = view.sarif_tags();
            let mut partial_fingerprints: BTreeMap<&'static str, String> = BTreeMap::new();
            partial_fingerprints.insert("codehound/v1", view.fingerprint());

            let codehound_evidence = view
                .evidence()
                .map(|evidence| serialize_evidence(view.rule_id(), evidence))
                .transpose()?;

            Ok(SarifResult {
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
                    codehound_evidence,
                    remediation: view.non_empty_remediation().map(str::to_string),
                    taint_show_paths: view.taint_show_paths(),
                },
            })
        })
        .collect::<Result<_, Error>>()?;

    let invocation = SarifInvocation {
        execution_successful: result.errors.is_empty(),
        end_time_utc: iso8601_utc_now(),
        working_directory: SarifArtifactLocation {
            uri: working_directory_uri(),
        },
        properties: (result.suppressed_count > 0).then_some(SarifInvocationProperties {
            suppressed_findings: result.suppressed_count,
        }),
    };

    let run_properties = result.stats.as_ref().map(|stats| SarifRunProperties {
        scan_stats: Some(stats),
        timing: stats.timing.as_ref(),
    });

    Ok(SarifLog {
        schema: super::schema::SCHEMA_URL,
        version: super::schema::SARIF_VERSION,
        runs: vec![SarifRun {
            tool: super::schema::SarifTool {
                driver: super::schema::SarifDriver {
                    name: "codehound",
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
    })
}

fn serialize_evidence<T: serde::Serialize>(
    rule_id: &str,
    evidence: &T,
) -> Result<serde_json::Value, Error> {
    serde_json::to_value(evidence).map_err(|source| Error::SarifEvidence {
        rule_id: rule_id.to_owned(),
        source,
    })
}

/// Process CWD as a stable URI for SARIF `workingDirectory` (not always `"."`).
fn working_directory_uri() -> &'static str {
    static CWD: OnceLock<String> = OnceLock::new();
    CWD.get_or_init(|| {
        std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".to_string())
    })
    .as_str()
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

#[cfg(test)]
mod tests {
    use serde::Serialize;
    use serde::ser::Error as _;

    use super::serialize_evidence;

    struct SerializationFails;

    impl Serialize for SerializationFails {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(S::Error::custom("deliberate test failure"))
        }
    }

    #[test]
    fn evidence_serialization_failure_retains_rule_context() {
        let error = serialize_evidence("CWE-79", &SerializationFails).unwrap_err();
        assert!(error.to_string().contains("CWE-79"), "error: {error}");
        assert!(error.to_string().contains("deliberate test failure"));
    }
}
