//! `.txt` text fixture format.

use std::path::Path;

use anyhow::{bail, Context, Result};

const SEPARATOR: &str = "---";
pub const FIXTURE_EXTENSION: &str = "txt";

/// Target language encoded in the fixture header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixtureLanguage {
    Go,
    Python,
    Rust,
}

impl FixtureLanguage {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_lowercase().as_str() {
            "go" => Ok(Self::Go),
            "python" | "py" => Ok(Self::Python),
            "rust" | "rs" => Ok(Self::Rust),
            other => bail!("unknown fixture language: {other}"),
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "py",
            Self::Rust => "rs",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "python",
            Self::Rust => "rust",
        }
    }
}

/// Parsed `.txt` fixture (header + source body).
#[derive(Debug, Clone)]
pub struct TextFixture {
    pub language: FixtureLanguage,
    pub filename: String,
    pub source: String,
}

impl TextFixture {
    /// Default output filename from the `.txt` path stem + language extension.
    pub fn default_filename(txt_path: &Path, language: FixtureLanguage) -> String {
        let stem = txt_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("fixture");
        format!("{stem}.{}", language.extension())
    }
}

/// Parse raw `.txt` fixture file contents.
pub fn parse_fixture(text: &str, txt_path: &Path) -> Result<TextFixture> {
    let (header, body) = split_header_body(text)?;
    let mut language = None;
    let mut filename = None;

    for line in header.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim().to_lowercase().as_str() {
            "lang" | "language" => language = Some(FixtureLanguage::parse(value)?),
            "file" | "filename" => filename = Some(value.trim().to_string()),
            _ => {}
        }
    }

    let language = language.context("fixture header missing `lang:` (go | python | rust)")?;
    let filename = filename.unwrap_or_else(|| TextFixture::default_filename(txt_path, language));
    let source = body.trim_start_matches('\n').to_string();

    Ok(TextFixture {
        language,
        filename,
        source,
    })
}

fn split_header_body(text: &str) -> Result<(&str, &str)> {
    if let Some(idx) = text.find(SEPARATOR) {
        let header = text[..idx].trim();
        let body = &text[idx + SEPARATOR.len()..];
        return Ok((header, body));
    }
    bail!("fixture must contain a `{SEPARATOR}` separator between header and source")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_header() {
        let text = "lang: python\n---\nimport re\n";
        let f = parse_fixture(text, Path::new("sample.txt")).unwrap();
        assert_eq!(f.language, FixtureLanguage::Python);
        assert_eq!(f.filename, "sample.py");
        assert!(f.source.contains("import re"));
    }
}
