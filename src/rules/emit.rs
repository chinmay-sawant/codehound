//! Helpers for building findings on detector hot paths.

use std::borrow::Cow;

use super::{DetectorEvidence, Finding, FindingInputs, LineCol, RuleMetadata, Severity};

/// Build a partial finding from rule metadata and location — shared by all
/// `push_finding_*` helpers.
fn finding_from_meta(
    meta: &RuleMetadata,
    file: &str,
    line: usize,
    col: usize,
    message: &str,
) -> Finding {
    Finding::new(FindingInputs {
        rule_id: meta.id,
        rule_title: meta.title,
        file: file.into(),
        location: LineCol { line, column: col },
        message: message.into(),
        severity: meta.severity,
        cwe: Cow::Borrowed(meta.cwe),
    })
}

/// Static rule metadata used by multiple detectors in one language bundle.
// ponytail: kept because generated code (build.rs → go_perf_metadata.rs) calls
// it pervasively (~100+ call sites) in const context where struct literal syntax
// would require repeating the field names for every rule.
pub const fn rule_meta(
    id: &'static str,
    title: &'static str,
    description: &'static str,
    severity: Severity,
    cwe: &'static [crate::cwe::CweRef],
    fix: Option<&'static str>,
) -> RuleMetadata {
    RuleMetadata {
        id,
        title,
        description,
        severity,
        cwe,
        fix,
    }
}

/// Push a finding using cached rule metadata and a precomputed file path.
pub fn push_finding(
    meta: &RuleMetadata,
    file: &str,
    line: usize,
    col: usize,
    message: &str,
    out: &mut Vec<Finding>,
) {
    out.push(finding_from_meta(meta, file, line, col, message));
}

/// Like [`push_finding`] with machine-readable evidence.
pub fn push_finding_with_evidence(
    meta: &RuleMetadata,
    file: &str,
    line: usize,
    col: usize,
    message: &str,
    evidence: DetectorEvidence,
    out: &mut Vec<Finding>,
) {
    let mut finding = finding_from_meta(meta, file, line, col, message).with_evidence(evidence);
    if let Some(fix) = meta.fix {
        finding = finding.with_fix(fix);
    }
    out.push(finding);
}

/// Like [`push_finding`] with snippet and fix text.
pub fn push_finding_with_snippet(
    meta: &RuleMetadata,
    file: &str,
    line: usize,
    col: usize,
    message: &str,
    snippet: impl Into<String>,
    out: &mut Vec<Finding>,
) {
    let mut finding = finding_from_meta(meta, file, line, col, message).with_snippet(snippet);
    if let Some(fix) = meta.fix {
        finding = finding.with_fix(fix);
    }
    out.push(finding);
}


