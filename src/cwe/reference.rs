//! CWE reference type.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CweRef {
    pub id: u32,
    pub name: &'static str,
    pub url: &'static str,
}

impl CweRef {
    pub const fn new(id: u32, name: &'static str, url: &'static str) -> Self {
        Self { id, name, url }
    }
}

/// Format CWE references as `"CWE-N (name), ..."` sorted by id.
pub fn format_cwe_list(cwes: &[CweRef]) -> String {
    let mut sorted: Vec<_> = cwes.iter().collect();
    sorted.sort_by_key(|c| c.id);
    sorted
        .iter()
        .map(|c| format!("CWE-{} ({})", c.id, c.name))
        .collect::<Vec<_>>()
        .join(", ")
}
