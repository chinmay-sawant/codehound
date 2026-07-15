//! Baseline store: entry types, discovery, and serialization.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::engine::io::write_atomic;
use crate::engine::path_walk::{WalkUpAction, walk_up_dirs};
use crate::engine::time::iso8601_utc_now;
use crate::rules::Finding;

pub const BASELINE_FILE_NAME: &str = ".codehound-baseline.json";
/// Wire format version. Optional fields use serde defaults so v1 files still load.
pub const BASELINE_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub fingerprint: String,
    /// Optional free-text reason (brownfield adoption notes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional ISO-8601 expiry; expired entries are ignored when filtering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

pub fn discover_baseline(cwd: &Path) -> Option<PathBuf> {
    walk_up_dirs(cwd, |current| {
        if current.join(BASELINE_FILE_NAME).is_file() {
            WalkUpAction::Found(current.join(BASELINE_FILE_NAME))
        } else if current.join(".git").is_dir() {
            WalkUpAction::Stop
        } else {
            WalkUpAction::Continue
        }
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: String,
    pub generated_at: String,
    pub tool_version: String,
    pub entries: HashMap<String, Vec<BaselineEntry>>,
}

impl Baseline {
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self::from_findings_with_meta(findings, None, None)
    }

    /// Build a baseline, optionally attaching `reason` / `expires` to every entry.
    pub fn from_findings_with_meta(
        findings: &[Finding],
        reason: Option<&str>,
        expires: Option<&str>,
    ) -> Self {
        let mut entries: HashMap<String, Vec<BaselineEntry>> = HashMap::new();
        for finding in findings {
            entries
                .entry(finding.rule_id.to_string())
                .or_default()
                .push(BaselineEntry {
                    file: finding.file.clone(),
                    line: finding.line,
                    column: finding.column,
                    fingerprint: finding.fingerprint_string(),
                    reason: reason.map(str::to_string),
                    expires: expires.map(str::to_string),
                });
        }

        Self {
            version: BASELINE_VERSION.to_string(),
            generated_at: iso8601_utc_now(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            entries,
        }
    }

    #[must_use = "baseline load failures must be handled"]
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let bytes = fs::read(path)?;
        let baseline: Self = serde_json::from_slice(&bytes)?;
        Ok(baseline)
    }

    pub fn to_file(&self, path: &Path) -> Result<(), Error> {
        write_atomic(path, self)
    }

    /// Match by fingerprint first (content-stable), then location (legacy / line-pin).
    /// Expired entries do not match.
    pub fn contains_finding(&self, finding: &Finding) -> bool {
        self.contains_finding_with_now(finding, &iso8601_utc_now())
    }

    pub fn contains_finding_with_now(&self, finding: &Finding, now_iso: &str) -> bool {
        if let Some(entries) = self.entries.get(finding.rule_id) {
            let fp = finding.fingerprint_string();
            let mut location_match = false;
            for entry in entries {
                if entry_expired(entry, now_iso) {
                    continue;
                }
                if entry.fingerprint == fp {
                    return true;
                }
                if entry.file == finding.file
                    && entry.line == finding.line
                    && entry.column == finding.column
                {
                    location_match = true;
                }
            }
            if location_match {
                return true;
            }
        }
        false
    }

    pub fn entry_count(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    /// Flat list of (rule_id, entry) for list/diff output.
    pub fn iter_entries(&self) -> impl Iterator<Item = (&str, &BaselineEntry)> {
        self.entries
            .iter()
            .flat_map(|(rule, entries)| entries.iter().map(move |e| (rule.as_str(), e)))
    }

    /// Drop entries whose fingerprints are not present in `live` findings.
    /// Returns the number of entries removed.
    pub fn prune_to_findings(&mut self, live: &[Finding]) -> usize {
        let live_fps: HashSet<String> = live.iter().map(Finding::fingerprint_string).collect();
        let mut removed = 0usize;
        for entries in self.entries.values_mut() {
            let before = entries.len();
            entries.retain(|e| live_fps.contains(&e.fingerprint));
            removed += before.saturating_sub(entries.len());
        }
        self.entries.retain(|_, v| !v.is_empty());
        removed
    }

    /// Merge live findings into the baseline (update fingerprints / add new).
    /// Returns (added, updated) counts.
    pub fn update_from_findings(&mut self, live: &[Finding]) -> (usize, usize) {
        let mut added = 0usize;
        let mut updated = 0usize;
        for finding in live {
            let rule = finding.rule_id.to_string();
            let fp = finding.fingerprint_string();
            let bucket = self.entries.entry(rule.clone()).or_default();
            if let Some(existing) = bucket.iter_mut().find(|e| {
                e.file == finding.file && e.line == finding.line && e.column == finding.column
            }) {
                if existing.fingerprint != fp {
                    existing.fingerprint = fp;
                    updated += 1;
                }
            } else if bucket.iter().any(|e| e.fingerprint == fp) {
                // already present by fingerprint
            } else {
                bucket.push(BaselineEntry {
                    file: finding.file.clone(),
                    line: finding.line,
                    column: finding.column,
                    fingerprint: fp,
                    reason: None,
                    expires: None,
                });
                added += 1;
            }
        }
        self.generated_at = iso8601_utc_now();
        self.tool_version = env!("CARGO_PKG_VERSION").to_string();
        (added, updated)
    }

    /// Findings present in baseline but not in live scan (stale baselined items).
    pub fn stale_entries<'a>(&'a self, live: &'a [Finding]) -> Vec<(&'a str, &'a BaselineEntry)> {
        let live_fps: HashSet<String> = live.iter().map(Finding::fingerprint_string).collect();
        let live_locs: HashSet<(String, String, usize, usize)> = live
            .iter()
            .map(|f| (f.rule_id.to_string(), f.file.clone(), f.line, f.column))
            .collect();
        self.iter_entries()
            .filter(|(rule, e)| {
                !live_fps.contains(&e.fingerprint)
                    && !live_locs.contains(&((*rule).to_string(), e.file.clone(), e.line, e.column))
            })
            .collect()
    }

    /// Live findings not covered by this baseline (new noise candidates).
    pub fn new_findings<'a>(&'a self, live: &'a [Finding]) -> Vec<&'a Finding> {
        live.iter().filter(|f| !self.contains_finding(f)).collect()
    }
}

fn entry_expired(entry: &BaselineEntry, now_iso: &str) -> bool {
    match &entry.expires {
        Some(exp) if !exp.is_empty() => exp.as_str() < now_iso,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{FindingInputs, LineCol, Severity};
    use std::borrow::Cow;

    fn finding(rule: &'static str, file: &str, line: usize, msg: &str) -> Finding {
        Finding::new(FindingInputs::new(
            rule,
            "t",
            file,
            LineCol { line, column: 1 },
            msg,
            Severity::High,
            Cow::Borrowed(&[]),
        ))
    }

    #[test]
    fn fingerprint_match_survives_line_shift_when_message_stable() {
        let f1 = finding("CWE-22", "a.go", 10, "path traversal");
        let base = Baseline::from_findings(&[f1]);
        // Same file + message, different line → still baselined via fingerprint.
        let f2 = finding("CWE-22", "a.go", 99, "path traversal");
        assert!(base.contains_finding(&f2));
        assert_eq!(base.entry_count(), 1);
    }

    #[test]
    fn prune_removes_stale_fingerprints() {
        let f1 = finding("CWE-22", "a.go", 10, "path traversal");
        let mut base = Baseline::from_findings(&[f1]);
        let removed = base.prune_to_findings(&[]);
        assert_eq!(removed, 1);
        assert_eq!(base.entry_count(), 0);
    }

    #[test]
    fn expired_entry_does_not_match() {
        let f = finding("CWE-22", "a.go", 1, "m");
        let base = Baseline::from_findings_with_meta(
            std::slice::from_ref(&f),
            None,
            Some("2000-01-01T00:00:00Z"),
        );
        assert!(!base.contains_finding_with_now(&f, "2026-07-11T00:00:00Z"));
    }
}
