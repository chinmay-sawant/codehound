//! Single-pass substring index for Go PERF detector hot paths.

/// Frequently scanned literals across the Go PERF bundle (one `contains` per needle).
pub const NEEDLES: &[&str] = &[
    "regexp.MustCompile(",
    "regexp.Compile(",
    "s += ",
    "s = s +",
    "make([]",
    "make(map[",
    "json.Marshal(",
    "json.Unmarshal(",
    "json.NewEncoder(",
    "json.NewDecoder(",
    "fmt.Sprintf(",
    "fmt.Fprintf(",
    "defer ",
    "time.Parse(",
    "time.ParseInLocation(",
    "url.Parse(",
    "url.ParseRequestURI(",
    "template.New(",
    "template.ParseFiles(",
    "template.Must(",
    "http.Client{",
    "http.Client{}",
    "&http.Client{",
    "db.Prepare(",
    "db.PrepareContext(",
    "time.After(",
    "filepath.Glob(",
    "os.ReadDir(",
    "strconv.Itoa(",
    "strconv.FormatInt(",
    "strconv.FormatUint(",
    "strconv.FormatFloat(",
    "bytes.Buffer{}",
    "new(bytes.Buffer)",
    "io.ReadAll(",
    "os.ReadFile(",
    "ioutil.ReadFile(",
    "bytes.NewReader(",
    "sha256.New(",
    "sha1.New(",
    "md5.New(",
    "hmac.New(",
    "rsa.GenerateKey(",
    "reflect.ValueOf(",
    "reflect.TypeOf(",
    "reflect.New(",
];

/// Precomputed presence of [`NEEDLES`] for one source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfSourceIndex {
    flags: Vec<bool>,
}

impl Default for PerfSourceIndex {
    fn default() -> Self {
        Self {
            flags: vec![false; NEEDLES.len()],
        }
    }
}

impl PerfSourceIndex {
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
