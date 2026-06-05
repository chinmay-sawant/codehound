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
    out.push(
        Finding::new(
            meta.id,
            meta.title,
            file,
            LineCol { line, column: col },
            message,
            meta.severity,
            Cow::Borrowed(meta.cwe),
        )
        .with_snippet(snippet)
        .with_fix(meta.fix.unwrap_or("")),
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn meta_with_cwe() -> RuleMetadata {
        rule_meta(
            "CWE-89",
            "SQL injection",
            "string-built SQL with user input",
            Severity::High,
            &[],
            None,
        )
    }

    #[test]
    fn push_finding_populates_fields() {
        let mut out = Vec::new();
        push_finding(&meta_with_cwe(), "a.go", 12, 5, "msg", &mut out);
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.rule_id, "CWE-89");
        assert_eq!(f.file, "a.go");
        assert_eq!(f.line, 12);
        assert_eq!(f.column, 5);
        assert_eq!(f.message, "msg");
        assert_eq!(f.severity, Severity::High);
        assert!(f.snippet.is_none());
        assert!(f.fix.is_none());
        assert!(f.cwe.is_none());
    }

    #[test]
    fn push_finding_with_snippet_attaches_snippet_and_fix() {
        let mut out = Vec::new();
        push_finding_with_snippet(
            &meta_with_cwe(),
            "a.go",
            1,
            1,
            "msg",
            "select * from users",
            &mut out,
        );
        assert_eq!(out.len(), 1);
        let f = &out[0];
        assert_eq!(f.snippet.as_deref(), Some("select * from users"));
        assert_eq!(f.fix.as_deref(), Some(""));
    }

    #[test]
    fn rule_meta_const_evaluable() {
        let m = rule_meta("X", "t", "d", Severity::Info, &[], None);
        assert_eq!(m.id, "X");
        assert_eq!(m.severity, Severity::Info);
        assert!(m.cwe.is_empty());
        assert!(m.fix.is_none());
    }
}
