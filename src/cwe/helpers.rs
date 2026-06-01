//! CWE lookup helpers for rule metadata.

use super::{CweRef, CWE_CATALOG};

/// Resolve CWE ids to static refs for `RuleMetadata`.
pub fn cwe_slice(ids: &[u32]) -> &'static [CweRef] {
    let v: Vec<CweRef> = ids
        .iter()
        .filter_map(|id| CWE_CATALOG.iter().find(|c| c.id == *id).cloned())
        .collect();
    Box::leak(v.into_boxed_slice())
}
