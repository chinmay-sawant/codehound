//! Helpers for building findings on detector hot paths.

use std::borrow::Cow;

use super::{Finding, LineCol, RuleMetadata, Severity};

/// Push a finding using cached rule metadata and a precomputed file path.
pub fn push_finding(
    meta: &RuleMetadata,
    file: &str,
    line: usize,
    col: usize,
    message: &str,
    out: &mut Vec<Finding>,
) {
    out.push(Finding::new(
        meta.id,
        meta.title,
        file,
        LineCol { line, column: col },
        message,
        meta.severity,
        Cow::Borrowed(meta.cwe),
    ));
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
    let mut finding = Finding::new(
        meta.id,
        meta.title,
        file,
        LineCol { line, column: col },
        message,
        meta.severity,
        Cow::Borrowed(meta.cwe),
    )
    .with_snippet(snippet);
    if let Some(fix) = meta.fix {
        finding = finding.with_fix(fix);
    }
    out.push(finding);
}

/// Static rule metadata used by multiple detectors in one language bundle.
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
