//! Baseline file support.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::rules::{FINGERPRINT_TOOL, FINGERPRINT_VERSION, Finding, Fingerprint};

pub const BASELINE_FILE_NAME: &str = ".slopguard-baseline.json";
pub const BASELINE_VERSION: &str = "1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: String,
    pub generated_at: String,
    pub tool_version: String,
    pub entries: HashMap<String, Vec<BaselineEntry>>,
    #[serde(skip)]
    fingerprint_index: HashSet<String>,
}

impl Baseline {
    pub fn from_findings(findings: &[Finding]) -> Self {
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
                });
        }

        let mut baseline = Self {
            version: BASELINE_VERSION.to_string(),
            generated_at: iso8601_utc_now(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            entries,
            fingerprint_index: HashSet::new(),
        };
        baseline.rebuild_index();
        baseline
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading baseline {}", path.display()))?;
        let mut baseline: Self = serde_json::from_str(&text)
            .with_context(|| format!("parsing baseline {}", path.display()))?;
        baseline.rebuild_index();
        Ok(baseline)
    }

    pub fn to_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating baseline directory {}", parent.display()))?;
        }
        let text = serde_json::to_string_pretty(self).context("serializing baseline")?;
        fs::write(path, format!("{text}\n"))
            .with_context(|| format!("writing baseline {}", path.display()))
    }

    pub fn contains(&self, rule_id: &str, file: &str, line: usize, column: usize) -> bool {
        let fingerprint = Fingerprint {
            tool: FINGERPRINT_TOOL.to_string(),
            version: FINGERPRINT_VERSION,
            rule_id: rule_id.to_string(),
            file: file.replace('\\', "/"),
            line,
            column,
        }
        .to_string();

        self.fingerprint_index.contains(&fingerprint)
            || self.entries.get(rule_id).is_some_and(|entries| {
                entries
                    .iter()
                    .any(|entry| entry.file == file && entry.line == line && entry.column == column)
            })
    }

    pub fn contains_finding(&self, finding: &Finding) -> bool {
        self.fingerprint_index
            .contains(&finding.fingerprint_string())
            || self.contains(finding.rule_id, &finding.file, finding.line, finding.column)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    fn rebuild_index(&mut self) {
        self.fingerprint_index.clear();
        for entries in self.entries.values() {
            for entry in entries {
                self.fingerprint_index.insert(entry.fingerprint.clone());
            }
        }
    }
}

pub fn discover_baseline(cwd: &Path) -> Option<PathBuf> {
    let mut current = if cwd.is_file() {
        cwd.parent()?.to_path_buf()
    } else {
        cwd.to_path_buf()
    };

    loop {
        let candidate = current.join(BASELINE_FILE_NAME);
        if candidate.is_file() {
            return Some(candidate);
        }
        if current.join(".git").is_dir() {
            return None;
        }
        if !current.pop() {
            return None;
        }
    }
}

fn iso8601_utc_now() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let (year, month, day, hour, minute, second) = unix_epoch_to_ymdhms(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn unix_epoch_to_ymdhms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;

    // Howard Hinnant's civil_from_days (public domain).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (
        y as u32,
        m as u32,
        d as u32,
        hour as u32,
        minute as u32,
        second as u32,
    )
}
