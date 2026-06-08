//! Static CWE catalog (curated subset relevant to Go performance / slop).
//!
//! Last reviewed against <https://cwe.mitre.org/data/definitions/>.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

use super::CweRef;

/// Deserialize an `id` field that may be either a JSON number (`15`) or a
/// JSON string (`"PERF-001"`). Always stores the canonical `String` form.
fn deserialize_id<'de, D: Deserializer<'de>>(de: D) -> Result<String, D::Error> {
    use serde::de::Error;
    let v = serde_json::Value::deserialize(de)?;
    match v {
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::String(s) => Ok(s),
        other => Err(D::Error::custom(format!(
            "expected id to be a number or string, got {other}"
        ))),
    }
}

pub const CWE_400: CweRef = CweRef::new(
    400,
    "Uncontrolled Resource Consumption",
    "https://cwe.mitre.org/data/definitions/400.html",
);

#[allow(dead_code)]
pub const CWE_405: CweRef = CweRef::new(
    405,
    "Asymmetric Resource Consumption (Amplification)",
    "https://cwe.mitre.org/data/definitions/405.html",
);

pub const CWE_407: CweRef = CweRef::new(
    407,
    "Algorithmic Complexity",
    "https://cwe.mitre.org/data/definitions/407.html",
);

pub const CWE_770: CweRef = CweRef::new(
    770,
    "Allocation of Resources Without Limits or Throttling",
    "https://cwe.mitre.org/data/definitions/770.html",
);

pub const CWE_1336: CweRef = CweRef::new(
    1336,
    "Improper Neutralization of Special Elements Used in a Template Engine",
    "https://cwe.mitre.org/data/definitions/1336.html",
);

#[allow(dead_code)]
pub const CWE_1041: CweRef = CweRef::new(
    1041,
    "Use of Redundant Code",
    "https://cwe.mitre.org/data/definitions/1041.html",
);

// -- auto-generated entries from golang.json follow --
include!(concat!(env!("OUT_DIR"), "/cwe_catalog_generated.rs"));

/// Curated CWE entries referenced by SlopGuard rules.
pub static CWE_CATALOG: &[CweRef] = CWE_CATALOG_GENERATED;

/// Precomposed slices for rule metadata (no runtime allocation).
pub static CWE_REFS_400_1336: &[CweRef] = &[CWE_400, CWE_1336];
pub static CWE_REFS_407: &[CweRef] = &[CWE_407];
pub static CWE_REFS_770: &[CweRef] = &[CWE_770];
pub static CWE_REFS_770_400: &[CweRef] = &[CWE_770, CWE_400];

/// Rich per-rule description loaded from `ruleset/golang/golang.json` (or a
/// custom path). Optional — when absent, callers fall back to the const
/// `META_CWE_*` metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDescription {
    /// Free-form rule id (e.g. `"22"` for CWE-22 or `"PERF-001"`).
    /// String because the JSON mix has both numeric and prefixed ids.
    #[serde(deserialize_with = "deserialize_id")]
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub original_description: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub detection_notes: String,
}

/// Load rule descriptions from a JSON file. The file is a map of rule ID
/// (e.g. `"CWE-22"`) → `RuleDescription`.
pub fn load_rule_descriptions(path: &Path) -> anyhow::Result<HashMap<String, RuleDescription>> {
    let text = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&text)?)
}

/// Default location of the Go ruleset, relative to the workspace root.
///
/// In development this resolves via `CARGO_MANIFEST_DIR` (obtained at compile
/// time from `env!`). At install time — when the ruleset JSON file is not
/// shipped alongside the binary — callers such as `--explain` fall back to
/// the compiled-in catalogue produced by `build.rs`.
pub fn default_ruleset_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("ruleset/golang/golang.json")
}

include!(concat!(env!("OUT_DIR"), "/rule_catalogue.rs"));
