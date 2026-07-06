//! Supported (or planned) languages.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LanguageId {
    Go,
    Python,
    /// Reserved for a future tree-sitter plugin; requires `typescript` feature.
    #[cfg(feature = "typescript")]
    TypeScript,
}

impl LanguageId {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "go" => Some(Self::Go),
            "py" => Some(Self::Python),
            #[cfg(feature = "typescript")]
            "ts" | "tsx" | "js" | "jsx" => Some(Self::TypeScript),
            _ => None,
        }
    }

    /// Parse a `codehound.toml` / operator language name (e.g. `go`, `python`, `py`).
    pub fn from_config_name(name: &str) -> Option<Self> {
        let name = name.trim();
        if name.eq_ignore_ascii_case("go") {
            Some(Self::Go)
        } else if name.eq_ignore_ascii_case("python") || name.eq_ignore_ascii_case("py") {
            Some(Self::Python)
        } else {
            #[cfg(feature = "typescript")]
            if name.eq_ignore_ascii_case("typescript") || name.eq_ignore_ascii_case("ts") {
                return Some(Self::TypeScript);
            }
            None
        }
    }

    pub fn config_names(self) -> &'static [&'static str] {
        match self {
            Self::Go => &["go"],
            Self::Python => &["python", "py"],
            #[cfg(feature = "typescript")]
            Self::TypeScript => &["typescript", "ts"],
        }
    }

    /// Canonical lowercase id used by the cache (`"go"`, `"python"`,
    /// `"typescript"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Python => "python",
            #[cfg(feature = "typescript")]
            Self::TypeScript => "typescript",
        }
    }

    /// Inverse of [`as_str`](Self::as_str) for cache hydration.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "go" => Some(Self::Go),
            "python" => Some(Self::Python),
            #[cfg(feature = "typescript")]
            "typescript" | "ts" => Some(Self::TypeScript),
            _ => None,
        }
    }
}
