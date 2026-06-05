//! A single finding emitted by a detector.

use std::borrow::Cow;

use serde::{Serialize, Serializer};

use super::Severity;
use crate::cwe::CweRef;

/// 1-indexed line and column in a source file.
#[derive(Debug, Clone, Copy)]
pub struct LineCol {
    pub line: usize,
    pub column: usize,
}

/// Serialize `Option<Box<[T]>>` so that `None` and `Some(&[])` both emit as
/// `[]` (preserves the historical wire shape for JSON consumers).
fn serialize_optional_cwe<S: Serializer>(
    cwe: &Option<Box<[CweRef]>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match cwe {
        Some(slice) => slice.serialize(serializer),
        None => Vec::<CweRef>::new().serialize(serializer),
    }
}

/// A single static-analysis finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Rule id, e.g. `CWE-89`.
    pub rule_id: &'static str,
    /// Rule title.
    pub rule_title: &'static str,
    /// File path (relative to the analyzed root when possible).
    pub file: String,
    /// 1-indexed line.
    pub line: usize,
    /// 1-indexed column.
    pub column: usize,
    /// Source snippet, if available.
    pub snippet: Option<String>,
    /// Free-form message.
    pub message: String,
    /// Severity.
    pub severity: Severity,
    /// Linked CWEs. `None` and `Some(&[])` both mean "no CWEs"; the
    /// `#[serde]` attribute ensures JSON output is always `[]` for either.
    #[serde(serialize_with = "serialize_optional_cwe")]
    pub cwe: Option<Box<[CweRef]>>,
    /// Optional suggestion.
    pub fix: Option<String>,
}

impl Finding {
    pub fn new(
        rule_id: &'static str,
        rule_title: &'static str,
        file: impl Into<String>,
        location: LineCol,
        message: impl Into<String>,
        severity: Severity,
        cwe: Cow<'static, [CweRef]>,
    ) -> Self {
        let cwe = if cwe.is_empty() {
            None
        } else {
            Some(cwe.into_owned().into_boxed_slice())
        };
        Self {
            rule_id,
            rule_title,
            file: file.into(),
            line: location.line,
            column: location.column,
            snippet: None,
            message: message.into(),
            severity,
            cwe,
            fix: None,
        }
    }

    pub fn with_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.snippet = Some(snippet.into());
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_builds_finding_with_no_snippet_or_fix() {
        let f = Finding::new(
            "CWE-89",
            "title",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        );
        assert_eq!(f.rule_id, "CWE-89");
        assert_eq!(f.rule_title, "title");
        assert_eq!(f.file, "a.go");
        assert_eq!(f.line, 1);
        assert_eq!(f.column, 1);
        assert_eq!(f.message, "msg");
        assert_eq!(f.severity, Severity::High);
        assert!(f.snippet.is_none());
        assert!(f.fix.is_none());
        assert!(f.cwe.is_none());
    }

    #[test]
    fn empty_cwe_slice_compiles_to_none() {
        let f = Finding::new(
            "X",
            "t",
            "f",
            LineCol { line: 1, column: 1 },
            "m",
            Severity::Info,
            Cow::Borrowed(&[]),
        );
        assert!(f.cwe.is_none(), "empty slice must collapse to None");
    }

    #[test]
    fn cwe_slice_with_entries_is_some() {
        let refs: &'static [CweRef] = Box::leak(Box::new([CweRef::new(
            89,
            "x",
            "https://example.com/89",
        )]));
        let f = Finding::new(
            "X",
            "t",
            "f",
            LineCol { line: 1, column: 1 },
            "m",
            Severity::Info,
            Cow::Borrowed(refs),
        );
        let cwes = f.cwe.expect("non-empty slice must produce Some");
        assert_eq!(cwes.len(), 1);
        assert_eq!(cwes[0].id, 89);
    }

    #[test]
    fn with_snippet_and_with_fix_chain() {
        let f = Finding::new(
            "X",
            "t",
            "f",
            LineCol { line: 1, column: 1 },
            "m",
            Severity::Info,
            Cow::Borrowed(&[]),
        )
        .with_snippet("the snippet")
        .with_fix("the fix");
        assert_eq!(f.snippet.as_deref(), Some("the snippet"));
        assert_eq!(f.fix.as_deref(), Some("the fix"));
    }

    #[test]
    fn file_accepts_string_or_str() {
        let owned: String = String::from("owned.go");
        let _ = Finding::new(
            "X",
            "t",
            owned,
            LineCol { line: 1, column: 1 },
            "m",
            Severity::Info,
            Cow::Borrowed(&[]),
        );
        let _ = Finding::new(
            "X",
            "t",
            "borrowed.go",
            LineCol { line: 1, column: 1 },
            "m",
            Severity::Info,
            Cow::Borrowed(&[]),
        );
    }

    #[test]
    fn cwe_serializes_as_empty_array_for_none() {
        let f = Finding::new(
            "X",
            "t",
            "f",
            LineCol { line: 1, column: 1 },
            "m",
            Severity::Info,
            Cow::Borrowed(&[]),
        );
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains("\"cwe\":[]"), "expected 'cwe':[], got: {s}");
    }
}
