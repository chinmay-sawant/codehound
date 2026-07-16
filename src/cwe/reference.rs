//! CWE reference type.

use serde::Serialize;

/// Static CWE catalogue reference used on findings and SARIF output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CweRef {
    /// Numeric CWE identifier.
    pub id: u32,
    /// Human-readable CWE name.
    pub name: &'static str,
    /// Canonical CWE reference URL.
    pub url: &'static str,
}

impl CweRef {
    /// Construct a static CWE reference.
    pub const fn new(id: u32, name: &'static str, url: &'static str) -> Self {
        Self { id, name, url }
    }
}

/// Format CWE references as `"CWE-N (name), ..."` sorted by id.
///
/// This function does not fail; it returns an empty string for an empty slice.
pub fn format_cwe_list(cwes: &[CweRef]) -> String {
    let mut sorted: Vec<_> = cwes.iter().collect();
    sorted.sort_by_key(|c| c.id);
    sorted
        .iter()
        .map(|c| format!("CWE-{} ({})", c.id, c.name))
        .collect::<Vec<_>>()
        .join(", ")
}
