//! SARIF 2.1.0 DTO types and constants.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

pub const SCHEMA_URL: &str = "https://json.schemastore.org/sarif-2.1.0.json";
pub const SARIF_VERSION: &str = "2.1.0";

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
    #[serde(rename = "codehoundScanStats", skip_serializing_if = "Option::is_none")]
    pub scan_stats: Option<&'a crate::engine::ScanStats>,
    #[serde(rename = "codehoundTiming", skip_serializing_if = "Option::is_none")]
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
    #[serde(rename = "shortDescription")]
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
    pub category: &'static str,
    #[serde(rename = "security-severity")]
    pub security_severity: &'static str,
    #[serde(rename = "codehoundEvidence", skip_serializing_if = "Option::is_none")]
    pub codehound_evidence: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(
        rename = "codehoundTaintShowPaths",
        skip_serializing_if = "Option::is_none"
    )]
    pub taint_show_paths: Option<bool>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifLocation<'a> {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation<'a>,
}

#[derive(Serialize)]
#[doc(hidden)]
pub struct SarifPhysicalLocation<'a> {
    #[serde(rename = "artifactLocation")]
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
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
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
