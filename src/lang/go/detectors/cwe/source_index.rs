//! Single-pass substring index for Go CWE detector hot paths.

/// Frequently scanned literals across the Go CWE bundle (one `contains` per needle).
pub const NEEDLES: &[&str] = &[
    "filepath.Join(",
    "filepath.Clean(",
    "filepath.Base(",
    "filepath.Abs(",
    "strings.HasPrefix(",
    "os.ReadFile",
    "os.Open(",
    "os.OpenFile",
    "os.Lstat(",
    "os.ModeSymlink",
    "sql.Open",
    "os.Getenv(",
    "os.LookupEnv",
    ".Query(",
    ".FormValue(",
    ".Param(",
    "exec.Command(",
    "template.HTML(",
    "html/template",
    "json.Unmarshal",
    "crypto/tls",
    "InsecureSkipVerify",
    "rand.Read(",
    "math/rand",
    "sync.Mutex",
    "http.ListenAndServe",
    "password",
    "Authorization",
    "hmac.New(",
    "cipher.NewGCM(",
    "aes.NewCipher(",
    "md5.Sum(",
    "sha1.Sum(",
    "CompareHashAndPassword",
    "ConstantTimeCompare",
];

/// Precomputed presence of [`NEEDLES`] for one source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIndex {
    flags: Vec<bool>,
}

impl Default for SourceIndex {
    fn default() -> Self {
        Self {
            flags: vec![false; NEEDLES.len()],
        }
    }
}

impl SourceIndex {
    pub fn build(source: &str) -> Self {
        let flags = NEEDLES
            .iter()
            .map(|needle| source.contains(needle))
            .collect();
        Self { flags }
    }

    #[inline]
    pub fn has(&self, needle: &str) -> bool {
        let Some(idx) = NEEDLES.iter().position(|n| *n == needle) else {
            return false;
        };
        self.flags.get(idx).copied().unwrap_or(false)
    }

    #[inline]
    pub fn has_any(&self, needles: &[&str]) -> bool {
        needles.iter().any(|n| self.has(n))
    }
}
