//! `.txt` text fixture format.

use std::path::Path;
use std::str::FromStr;

use thiserror::Error;

const SEPARATOR: &str = "---";
/// File extension used for text fixtures (without the leading dot).
pub const FIXTURE_EXTENSION: &str = "txt";

/// Typed failures while parsing or materializing a text fixture.
#[derive(Debug, Error)]
pub enum FixtureError {
    /// Header named an unsupported language.
    #[error("unknown fixture language: {0}")]
    UnknownLanguage(String),
    /// Header omitted the required `lang:` field.
    #[error("fixture header missing `lang:` (go | python)")]
    MissingLanguage,
    /// Missing `---` separator between header and source body.
    #[error("fixture must contain a `{0}` separator between header and source")]
    MissingSeparator(&'static str),
    /// Filename header used an absolute path.
    #[error("fixture filename must be relative, got absolute path {0:?}")]
    AbsoluteFilename(String),
    /// Filename header contained a parent-directory segment.
    #[error("fixture filename must not contain '..': {0:?}")]
    ParentFilename(String),
    /// Materialized path would escape the output root.
    #[error("fixture path escapes materialize root: {0}")]
    EscapedPath(String),
    /// Directory walk failed while discovering fixtures.
    #[error("fixture traversal failed: {0}")]
    Walk(String),
    /// Filesystem failure while reading or writing a fixture.
    #[error("{operation} {path}: {source}")]
    Io {
        /// Operation label (`"read"`, `"write"`, …).
        operation: &'static str,
        /// Path involved in the failure.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Target language encoded in the fixture header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixtureLanguage {
    /// Go source fixture.
    Go,
    /// Python source fixture.
    Python,
}

impl FromStr for FixtureLanguage {
    type Err = FixtureError;

    /// # Errors
    ///
    /// Returns [`FixtureError::UnknownLanguage`] when the value is not a
    /// supported fixture language.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "go" => Ok(Self::Go),
            "python" | "py" => Ok(Self::Python),
            other => Err(FixtureError::UnknownLanguage(other.to_string())),
        }
    }
}

impl FixtureLanguage {
    /// Return the source-file extension for this language.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "py",
        }
    }

    /// Return the canonical header spelling for this language.
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
    /// Language declared in the fixture header.
    pub language: FixtureLanguage,
    /// Relative output filename for the materialized source.
    pub filename: String,
    /// Source body below the header separator.
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
///
/// # Errors
///
/// Returns [`FixtureError`] when the separator, language header, or fixture
/// metadata is malformed.
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
