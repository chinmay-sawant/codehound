//! Rich per-rule description loaded from `ruleset/golang/golang.json` (or a
//! custom path). Optional — when absent, callers fall back to the const
//! `META_CWE_*` metadata.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize};

use crate::Error;

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
///
/// # Errors
///
/// Returns [`Error::Io`] on read failure and [`Error::Json`] when the file is
/// not valid JSON for the expected schema.
#[must_use = "rule catalogue load failures must be handled"]
pub fn load_rule_descriptions(path: &Path) -> Result<HashMap<String, RuleDescription>, Error> {
    let text = std::fs::read_to_string(path).map_err(Error::from)?;
    serde_json::from_str(&text).map_err(Error::from)
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
