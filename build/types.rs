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
