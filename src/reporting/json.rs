//! JSON reporter.
//!
//! Two output modes:
//! - **NDJSON** (default): one finding per line, stream-friendly
//! - **Envelope** (`--json-envelope`): a single JSON object wrapping the
//!   run metadata + findings array

use std::io::Write;

use anyhow::Result;
use serde::Serialize;

use crate::cwe::CweRef;
use crate::engine::AnalysisResult;

pub fn print(result: &AnalysisResult) -> Result<()> {
    print_ndjson(result)
}

pub fn print_envelope(result: &AnalysisResult) -> Result<()> {
    let envelope = Envelope::from(result);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, &envelope)?;
    out.write_all(b"\n")?;
    Ok(())
}

fn print_ndjson(result: &AnalysisResult) -> Result<()> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for f in &result.findings {
        let j = FindingJson::from(f);
        serde_json::to_writer(&mut out, &j)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// JSON shape used in the envelope mode. The inner `findings` field is a
/// `Vec<FindingJson>` so we can attach a `fingerprint` per finding.
#[derive(Serialize)]
struct Envelope<'a> {
    tool: &'a str,
    version: &'a str,
    schema: &'static str,
    #[serde(rename = "findingCount")]
    finding_count: usize,
    #[serde(rename = "errorCount")]
    error_count: usize,
    findings: Vec<FindingJson<'a>>,
}

impl<'a> From<&'a AnalysisResult> for Envelope<'a> {
    fn from(r: &'a AnalysisResult) -> Self {
        Self {
            tool: "slopguard",
            version: env!("CARGO_PKG_VERSION"),
            schema: "https://json.schemastore.org/slopguard/v1",
            finding_count: r.findings.len(),
            error_count: r.errors.len(),
            findings: r.findings.iter().map(FindingJson::from).collect(),
        }
    }
}

/// `Finding` rendered to JSON with derived `fingerprint`. We carry the
/// `CweRef` array as a `Vec<DisplayCweRef>` so each `id` is emitted as
/// `"CWE-N"` rather than the raw `u32`.
#[derive(Serialize)]
struct FindingJson<'a> {
    rule_id: &'a str,
    rule_title: &'a str,
    file: &'a str,
    line: usize,
    column: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_column: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    byte_offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    byte_length: Option<usize>,
    fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<&'a str>,
    message: &'a str,
    severity: crate::rules::Severity,
    cwe: Vec<DisplayCweRef<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<&'a str>,
}

/// `CweRef` with `id` rendered as `"CWE-N"`.
#[derive(Serialize)]
struct DisplayCweRef<'a> {
    id: String,
    name: &'a str,
    url: &'a str,
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
        let cwe: Vec<DisplayCweRef<'_>> = f
            .cwe
            .as_deref()
            .map(|s| s.iter().map(DisplayCweRef::from).collect())
            .unwrap_or_default();
        Self {
            rule_id: f.rule_id,
            rule_title: f.rule_title,
            file: f.file.as_str(),
            line: f.line,
            column: f.column,
            end_line: f.end_line,
            end_column: f.end_column,
            byte_offset: f.byte_offset,
            byte_length: f.byte_length,
            fingerprint: f.fingerprint(),
            snippet: f.snippet.as_deref(),
            message: f.message.as_str(),
            severity: f.severity,
            cwe,
            fix: f.fix.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Finding, LineCol, Severity};
    use std::borrow::Cow;

    fn sample() -> AnalysisResult {
        AnalysisResult {
            findings: vec![Finding::new(
                "CWE-89",
                "SQL injection",
                "a.go",
                LineCol { line: 12, column: 5 },
                "user input is concatenated into the query",
                Severity::High,
                Cow::Borrowed(&[]),
            )],
            errors: vec![],
        }
    }

    fn sample_with_cwe() -> AnalysisResult {
        let cwes: &'static [CweRef] = Box::leak(Box::new([CweRef::new(
            89,
            "SQL Injection",
            "https://cwe.mitre.org/data/definitions/89.html",
        )]));
        AnalysisResult {
            findings: vec![Finding::new(
                "CWE-89",
                "SQL injection",
                "a.go",
                LineCol { line: 1, column: 1 },
                "msg",
                Severity::High,
                Cow::Borrowed(cwes),
            )],
            errors: vec![],
        }
    }

    #[test]
    fn envelope_has_tool_version_and_finding_count() {
        let r = sample();
        let env = Envelope::from(&r);
        let s = serde_json::to_string_pretty(&env).unwrap();
        assert!(s.contains("\"tool\": \"slopguard\""), "got: {s}");
        assert!(s.contains("\"version\""), "got: {s}");
        assert!(s.contains("\"findingCount\": 1"), "got: {s}");
        assert!(s.contains("\"errorCount\": 0"), "got: {s}");
    }

    #[test]
    fn envelope_serializes_finding_fingerprint() {
        let r = sample();
        let env = Envelope::from(&r);
        let s = serde_json::to_string_pretty(&env).unwrap();
        assert!(
            s.contains("\"fingerprint\": \"CWE-89:a.go:12:5\""),
            "got: {s}"
        );
    }

    #[test]
    fn cwe_id_serialized_as_cwe_n_string() {
        let r = sample_with_cwe();
        let env = Envelope::from(&r);
        let s = serde_json::to_string_pretty(&env).unwrap();
        assert!(s.contains("\"id\": \"CWE-89\""), "got: {s}");
    }

    #[test]
    fn ndjson_emits_one_finding_per_line() {
        let result = AnalysisResult {
            findings: vec![
                Finding::new(
                    "CWE-1",
                    "a",
                    "a.go",
                    LineCol { line: 1, column: 1 },
                    "m1",
                    Severity::Info,
                    Cow::Borrowed(&[]),
                ),
                Finding::new(
                    "CWE-2",
                    "b",
                    "b.go",
                    LineCol { line: 2, column: 2 },
                    "m2",
                    Severity::Info,
                    Cow::Borrowed(&[]),
                ),
            ],
            errors: vec![],
        };
        let mut buf = Vec::new();
        for f in &result.findings {
            serde_json::to_writer(&mut buf, &FindingJson::from(f)).unwrap();
            buf.push(b'\n');
        }
        let s = std::str::from_utf8(&buf).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines.len(), 2, "expected 2 NDJSON lines, got: {s}");
        assert!(lines[0].contains("\"rule_id\":\"CWE-1\""), "got: {}", lines[0]);
        assert!(lines[1].contains("\"rule_id\":\"CWE-2\""), "got: {}", lines[1]);
    }

    #[test]
    fn envelope_with_errors_includes_error_count() {
        let r = {
            let mut r = sample();
            r.errors = vec![crate::engine::ScanError {
                path: std::path::PathBuf::from("x.go"),
                kind: crate::engine::ScanErrorKind::Io,
                message: "permission denied".to_string(),
            }];
            r
        };
        let env = Envelope::from(&r);
        let s = serde_json::to_string_pretty(&env).unwrap();
        assert!(s.contains("\"errorCount\": 1"), "got: {s}");
    }
}
