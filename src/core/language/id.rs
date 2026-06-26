//! Supported (or planned) languages.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LanguageId {
    Go,
    Python,
    TypeScript,
}

impl LanguageId {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "go" => Some(Self::Go),
            "py" => Some(Self::Python),
            "ts" | "tsx" | "js" | "jsx" => Some(Self::TypeScript),
            _ => None,
        }
    }

    /// Parse a `slopguard.toml` / operator language name (e.g. `go`, `python`, `py`).
    pub fn from_config_name(name: &str) -> Option<Self> {
        match name.trim().to_lowercase().as_str() {
            "go" => Some(Self::Go),
            "python" | "py" => Some(Self::Python),
            "typescript" | "ts" => Some(Self::TypeScript),
            _ => None,
        }
    }

    pub fn config_names(self) -> &'static [&'static str] {
        match self {
            Self::Go => &["go"],
            Self::Python => &["python", "py"],
            Self::TypeScript => &["typescript", "ts"],
        }
    }

    /// Canonical lowercase id used by the cache (`"go"`, `"python"`,
    /// `"typescript"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "python",
            Self::TypeScript => "typescript",
        }
    }

    /// Inverse of [`as_str`](Self::as_str) for cache hydration.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "go" => Some(Self::Go),
            "python" => Some(Self::Python),
            "typescript" | "ts" => Some(Self::TypeScript),
            _ => None,
        }
    }
}
