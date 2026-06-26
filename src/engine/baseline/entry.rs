//! Baseline file entry + private location-key.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct BaselineLocationKey {
    pub(super) rule_id: String,
    pub(super) file: String,
    pub(super) line: usize,
    pub(super) column: usize,
}
