//! Analysis output container.

use std::path::PathBuf;

use crate::rules::Finding;

/// A non-fatal error encountered while scanning a single file. The scan
/// continues; this entry is reported so the caller can surface it.
#[derive(Debug, Clone)]
pub struct ScanError {
    pub path: PathBuf,
    pub kind: ScanErrorKind,
    pub message: String,
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

impl std::error::Error for ScanError {}

/// Coarse error category — used to map to distinct process exit codes
/// (config / I-O / parse / engine-internal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanErrorKind {
    /// Failure reading the file or its parent directory.
    Io,
    /// Source bytes were not valid UTF-8.
    Encoding,
    /// Tree-sitter failed to produce a tree.
    Parse,
    /// A detector raised an error during `run`.
    Engine,
}

impl ScanErrorKind {
    /// Maps to the conventional process exit code for this category.
    pub fn exit_code(self) -> u8 {
        match self {
            ScanErrorKind::Io => 3,
            ScanErrorKind::Encoding => 3,
            ScanErrorKind::Parse => 3,
            ScanErrorKind::Engine => 3,
        }
    }
}

/// Findings (and per-file errors) from a scan run.
#[derive(Debug, Default, Clone)]
pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    /// Non-fatal per-file errors collected during the scan. The scan does
    /// NOT abort on the first error; instead, the caller decides whether
    /// `errors` should fail the run.
    pub errors: Vec<ScanError>,
}

impl AnalysisResult {
    pub fn should_fail(&self, policy: crate::core::FailPolicy) -> bool {
        self.findings.iter().any(|f| policy.should_fail(f.severity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_fail_returns_false_when_no_findings() {
        let result = AnalysisResult::default();
        assert!(!result.should_fail(crate::core::FailPolicy::WarningsAsErrors));
    }

    #[test]
    fn scan_error_displays_path_and_message() {
        let e = ScanError {
            path: PathBuf::from("/tmp/x.go"),
            kind: ScanErrorKind::Io,
            message: "permission denied".to_string(),
        };
        assert_eq!(format!("{e}"), "/tmp/x.go: permission denied");
    }

    #[test]
    fn error_kind_maps_to_exit_codes() {
        assert_eq!(ScanErrorKind::Io.exit_code(), 3);
        assert_eq!(ScanErrorKind::Encoding.exit_code(), 3);
        assert_eq!(ScanErrorKind::Parse.exit_code(), 3);
        assert_eq!(ScanErrorKind::Engine.exit_code(), 3);
    }

    #[test]
    fn analysis_result_carries_errors_field() {
        let result = AnalysisResult {
            findings: vec![],
            errors: vec![ScanError {
                path: PathBuf::from("a.go"),
                kind: ScanErrorKind::Encoding,
                message: "not utf-8".to_string(),
            }],
        };
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].kind, ScanErrorKind::Encoding);
    }
}
