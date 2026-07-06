//! JSON DTO types: `Envelope`, `FindingJson`, `DisplayCweRef`, plus `From`
//! impls.

use serde::Serialize;

use crate::cwe::CweRef;
use crate::engine::AnalysisResult;
use crate::engine::ScanStats;
use crate::rules::FindingView;

fn is_false(value: &bool) -> bool {
    !*value
}

/// JSON shape used in the envelope mode. The inner `findings` field is a
/// `Vec<FindingJson>` so we can attach a `fingerprint` per finding.
#[derive(Serialize)]
#[doc(hidden)]
pub struct Envelope<'a> {
    pub tool: &'a str,
    pub version: &'a str,
    pub schema: &'static str,
    #[serde(rename = "findingCount")]
    pub finding_count: usize,
    #[serde(rename = "errorCount")]
    pub error_count: usize,
    #[serde(rename = "suppressedCount")]
    pub suppressed_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<&'a ScanStats>,
    pub findings: Vec<FindingJson<'a>>,
}

impl<'a> From<&'a AnalysisResult> for Envelope<'a> {
    fn from(r: &'a AnalysisResult) -> Self {
        Self {
            tool: "slopguard",
            version: env!("CARGO_PKG_VERSION"),
            schema: "https://json.schemastore.org/slopguard/v1",
            finding_count: r.findings.len(),
            error_count: r.errors.len(),
            suppressed_count: r.suppressed_count,
            stats: r.stats.as_ref(),
            findings: r.findings.iter().map(FindingJson::from).collect(),
        }
    }
}

/// `Finding` rendered to JSON with derived `fingerprint`. We carry the
/// `CweRef` array as a `Vec<DisplayCweRef>` so each `id` is emitted as
/// `"CWE-N"` rather than the raw `u32`.
#[derive(Serialize)]
#[doc(hidden)]
pub struct FindingJson<'a> {
    pub rule_id: &'a str,
    pub rule_title: &'a str,
    pub category: &'static str,
    pub file: &'a str,
    pub line: usize,
    pub column: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_length: Option<usize>,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<&'a str>,
    pub message: &'a str,
    pub severity: crate::rules::Severity,
    pub cwe: Vec<DisplayCweRef<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<&'a crate::rules::DetectorEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<&'a [String]>,
    #[serde(skip_serializing_if = "is_false")]
    pub suppressed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_show_paths: Option<bool>,
}

/// `CweRef` with `id` rendered as `"CWE-N"`.
#[derive(Serialize)]
#[doc(hidden)]
pub struct DisplayCweRef<'a> {
    pub id: String,
    pub name: &'a str,
    pub url: &'a str,
}

impl<'a> From<&'a CweRef> for DisplayCweRef<'a> {
    fn from(c: &'a CweRef) -> Self {
        Self {
            id: format!("CWE-{}", c.id),
            name: c.name,
            url: c.url,
        }
    }
}

impl<'a> From<&'a crate::rules::Finding> for FindingJson<'a> {
    fn from(f: &'a crate::rules::Finding) -> Self {
        let view = FindingView::new(f);
        let f = view.inner();
        let cwe: Vec<DisplayCweRef<'_>> = view
            .non_empty_cwe()
            .map(|s| s.iter().map(DisplayCweRef::from).collect())
            .unwrap_or_default();
        Self {
            rule_id: f.rule_id,
            rule_title: f.rule_title,
            category: view.category(),
            file: f.file.as_str(),
            line: f.line,
            column: f.column,
            end_line: f.end_line,
            end_column: f.end_column,
            byte_offset: f.byte_offset,
            byte_length: f.byte_length,
            fingerprint: view.fingerprint(),
            snippet: f.snippet.as_deref(),
            message: f.message.as_str(),
            severity: f.severity,
            cwe,
            fix: view.non_empty_fix(),
            evidence: f.evidence.as_ref(),
            confidence: f.confidence,
            tags: view.non_empty_tags(),
            suppressed: f.suppressed,
            remediation: view.non_empty_remediation(),
            taint_show_paths: f
                .evidence
                .as_ref()
                .and_then(crate::rules::DetectorEvidence::taint_show_paths_flag),
        }
    }
}
