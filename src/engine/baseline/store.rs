//! Baseline store: in-memory indexed baseline + serialization.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::rules::Finding;

use super::entry::{BaselineEntry, BaselineLocationKey};
use super::io::iso8601_utc_now;

pub const BASELINE_VERSION: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub version: String,
    pub generated_at: String,
    pub tool_version: String,
    pub entries: HashMap<String, Vec<BaselineEntry>>,
    #[serde(skip)]
    fingerprint_index: HashSet<String>,
    #[serde(skip)]
    location_index: HashSet<BaselineLocationKey>,
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
            location_index: HashSet::new(),
        };
        baseline.rebuild_index();
        baseline
    }

    #[must_use = "baseline load failures must be handled"]
    pub fn from_file(path: &Path) -> Result<Self, Error> {
        let bytes = fs::read(path)?;
        let mut baseline: Self = serde_json::from_slice(&bytes)?;
        baseline.rebuild_index();
        Ok(baseline)
    }

    pub fn to_file(&self, path: &Path) -> Result<(), Error> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let text = serde_json::to_string_pretty(self)?;
        fs::write(path, format!("{text}\n"))?;
        Ok(())
    }

    pub fn contains_finding(&self, finding: &Finding) -> bool {
        self.location_index.contains(&BaselineLocationKey {
            rule_id: finding.rule_id.to_string(),
            file: finding.file.clone(),
            line: finding.line,
            column: finding.column,
        }) || self
            .fingerprint_index
            .contains(&finding.fingerprint_string())
    }

    pub fn entry_count(&self) -> usize {
        self.entries.values().map(Vec::len).sum()
    }

    fn rebuild_index(&mut self) {
        self.fingerprint_index.clear();
        self.location_index.clear();
        let entry_count = self.entry_count();
        self.fingerprint_index.reserve(entry_count);
        self.location_index.reserve(entry_count);
        for (rule_id, entries) in &self.entries {
            for entry in entries {
                self.fingerprint_index.insert(entry.fingerprint.clone());
                self.location_index.insert(BaselineLocationKey {
                    rule_id: rule_id.clone(),
                    file: entry.file.clone(),
                    line: entry.line,
                    column: entry.column,
                });
            }
        }
    }
}
