use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub fixture: Vec<FixtureEntry>,
}

#[derive(Debug, Deserialize)]
pub struct FixtureEntry {
    pub lang: String,
    pub path: String,
    pub required_rules: Vec<String>,
    #[serde(default)]
    pub taint: bool,
}

pub fn load_manifest() -> Manifest {
    let text = std::fs::read_to_string("tests/fixtures/manifest.toml")
        .expect("tests/fixtures/manifest.toml is mandatory");
    toml::from_str(&text).expect("parse manifest.toml")
}
