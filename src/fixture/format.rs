//! `.txt` text fixture format.

use std::path::Path;
use std::str::FromStr;

use thiserror::Error;

const SEPARATOR: &str = "---";
pub const FIXTURE_EXTENSION: &str = "txt";

/// Typed failures while parsing or materializing a text fixture.
#[derive(Debug, Error)]
pub enum FixtureError {
    #[error("unknown fixture language: {0}")]
    UnknownLanguage(String),
    #[error("fixture header missing `lang:` (go | python)")]
    MissingLanguage,
    #[error("fixture must contain a `{0}` separator between header and source")]
    MissingSeparator(&'static str),
    #[error("fixture filename must be relative, got absolute path {0:?}")]
    AbsoluteFilename(String),
    #[error("fixture filename must not contain '..': {0:?}")]
    ParentFilename(String),
    #[error("fixture path escapes materialize root: {0}")]
    EscapedPath(String),
    #[error("fixture traversal failed: {0}")]
    Walk(String),
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Target language encoded in the fixture header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixtureLanguage {
    Go,
    Python,
}

impl FromStr for FixtureLanguage {
    type Err = FixtureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "go" => Ok(Self::Go),
            "python" | "py" => Ok(Self::Python),
            other => Err(FixtureError::UnknownLanguage(other.to_string())),
        }
    }
}

impl FixtureLanguage {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "py",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "python",
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
pub fn parse_fixture(text: &str, txt_path: &Path) -> Result<TextFixture, FixtureError> {
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
            "lang" | "language" => language = Some(value.parse()?),
            "file" | "filename" => filename = Some(value.trim().to_string()),
            _ => {}
        }
    }

    let language = language.ok_or(FixtureError::MissingLanguage)?;
    let filename = filename.unwrap_or_else(|| TextFixture::default_filename(txt_path, language));
    let source = body.trim_start_matches('\n').to_string();

    Ok(TextFixture {
        language,
        filename,
        source,
    })
}

fn split_header_body(text: &str) -> Result<(&str, &str), FixtureError> {
    if let Some(idx) = text.find(SEPARATOR) {
        let header = text[..idx].trim();
        let body = &text[idx + SEPARATOR.len()..];
        return Ok((header, body));
    }
    Err(FixtureError::MissingSeparator(SEPARATOR))
}
