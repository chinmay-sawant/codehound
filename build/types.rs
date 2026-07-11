use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RegistryFile {
    pub detector: Vec<RegistryDetector>,
}

#[derive(Debug, Deserialize)]
pub struct RegistryDetector {
    pub cwe: u32,
    // Deserialized for registry layout validation; not read after parse.
    #[expect(dead_code)]
    pub domain: String,
    pub function: String,
}

impl RegistryDetector {
    pub fn validate(&self) {
        validate_function_ident("CWE", self.cwe, &self.function);
    }
}

#[derive(Debug, Deserialize)]
pub struct PerfRegistryFile {
    pub detector: Vec<PerfRegistryDetector>,
}

#[derive(Debug, Deserialize)]
pub struct PerfRegistryDetector {
    pub perf: u32,
    // Deserialized for registry layout validation; not read after parse.
    #[expect(dead_code)]
    pub domain: String,
    pub function: String,
}

impl PerfRegistryDetector {
    pub fn validate(&self) {
        validate_function_ident("PERF", self.perf, &self.function);
    }
}

/// Registry `function` must be a Rust identifier: `^[A-Za-z_][A-Za-z0-9_]*$`.
fn validate_function_ident(kind: &str, id: u32, function: &str) {
    let ok = !function.is_empty()
        && function
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && function
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        panic!(
            "{kind}-{id}: invalid function identifier `{function}` (expected ^[A-Za-z_][A-Za-z0-9_]*$)"
        );
    }
}

#[derive(Debug, Clone)]
pub struct JsonRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub _original_description: String,
    pub _category: String,
    pub detection_notes: String,
    pub severity: Option<String>,
}
