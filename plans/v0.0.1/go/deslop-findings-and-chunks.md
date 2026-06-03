# Deslop: Scan Pipeline, Finding Generation & Export

A detailed architectural reference covering how **deslop** scans repositories, generates findings, exports context, and produces chunk files. Use this as a blueprint for reimplementation.

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [CLI Entry Point & Configuration Flow](#2-cli-entry-point--configuration-flow)
3. [Scan Pipeline (Orchestration)](#3-scan-pipeline-orchestration)
4. [File Discovery (Walker)](#4-file-discovery-walker)
5. [File Analysis & Parsing](#5-file-analysis--parsing)
6. [Language-Specific Parsing](#6-language-specific-parsing)
7. [Index Building](#7-index-building)
8. [Rule Evaluation (Heuristics Engine)](#8-rule-evaluation-heuristics-engine)
9. [Finding Model](#9-finding-model)
10. [Export: Context & Chunk Generation](#10-export-context--chunk-generation)
11. [Report Formatting](#11-report-formatting)
12. [Key Data Flow Diagram](#12-key-data-flow-diagram)
13. [Appendix: Directory Structure](#13-appendix-directory-structure)

---

## 1. High-Level Architecture

The crate is layered from parsing to reporting:

```
┌─────────────────────────────────────────────────────┐
│                     main.rs                         │
│            CLI entry point (clap parse)              │
├─────────────────────────────────────────────────────┤
│                   cli/  (dispatchers)                │
│          execute_scan, execute_bench, execute_rules  │
├─────────────────────────────────────────────────────┤
│                   scan/  (orchestrator)              │
│       discover → parse → index → evaluate → export  │
├─────────────────────────────────────────────────────┤
│              heuristics/  (rule engine)              │
│    shared + language-specific rule evaluation        │
├───────────────────┬──────────────────┬───────────────┤
│   analysis/       │   index/         │  model/       │
│   (parsing, AST)  │   (repo index)   │  (types)      │
├───────────────────┴──────────────────┴───────────────┤
│  export/   (context & chunk file generation)         │
└─────────────────────────────────────────────────────┘
```

**Source:** `src/lib.rs:1-13`

---

## 2. CLI Entry Point & Configuration Flow

### 2.1 CLI Subcommands (`src/main.rs`)

```rust
// main.rs:24-83
enum Command {
    Scan {
        path: PathBuf,
        #[arg(long)] json: bool,
        #[arg(long)] details: bool,
        #[arg(long)] no_ignore: bool,
        #[arg(long)] enable_semantic: bool,
        #[arg(long)] experimental: bool,
        #[arg(long, value_delimiter = ',')] ignore: Vec<String>,
        #[arg(long)] no_fail: bool,
        #[arg(long)] no_context: bool,
        #[arg(long)] no_chunks: bool,
        #[arg(long, default_value_t = 25)] chunk_size: usize,
        #[arg(long, default_value = "scripts/findings/functions")]
        context_output_dir: PathBuf,
        #[arg(long, default_value = "scripts/chunks")]
        chunks_output_dir: PathBuf,
    },
    Bench { path, repeats, warmups, json, no_ignore, enable_semantic, experimental },
    Rules { json, language, status },
}
```

### 2.2 Configuration Structs

**ScanCommandOptions** — CLI-parsed options (`src/cli/mod.rs:15-29`):

```rust
pub(crate) struct ScanCommandOptions {
    pub(crate) path: PathBuf,
    pub(crate) json: bool,
    pub(crate) details: bool,
    pub(crate) no_ignore: bool,
    pub(crate) enable_semantic: bool,
    pub(crate) experimental: bool,
    pub(crate) ignore: Vec<String>,
    pub(crate) no_fail: bool,
    pub(crate) no_context: bool,
    pub(crate) no_chunks: bool,
    pub(crate) chunk_size: usize,
    pub(crate) context_output_dir: PathBuf,
    pub(crate) chunks_output_dir: PathBuf,
}
```

**ScanOptions** — Engine-only options (`src/model/scan.rs:8-12`):

```rust
pub struct ScanOptions {
    pub root: PathBuf,
    pub respect_ignore: bool,
}
```

Note: `ScanOptions` does **not** carry export options (chunk_size, directories, etc.). Export configuration is handled separately via `ExportOptions`.

**ExportOptions** (`src/export/writer.rs:11-19`):

```rust
pub struct ExportOptions {
    pub export_context: bool,
    pub export_chunks: bool,
    pub chunk_size: usize,
    pub context_output_dir: PathBuf,
    pub chunks_output_dir: PathBuf,
    pub details: bool,
}
```

**RepoConfig** — From `.deslop.toml` (`src/config.rs`):

```rust
pub(crate) struct RepoConfig {
    pub go_semantic_experimental: bool,
    pub rust_async_experimental: bool,
    pub disabled_rules: Vec<String>,
    pub suppressed_paths: Vec<PathBuf>,
    pub severity_overrides: BTreeMap<String, Severity>,
}
```

### 2.3 Execute Scan Flow (`src/cli/mod.rs:31-100`)

```
execute_scan(options):
  1. scan_repository_with_experimentals(ScanOptions { root, respect_ignore }, ...)
     → returns ScanOutput { report: ScanReport, parsed_files: Vec<ParsedFile> }

  2. Filter findings by --ignore list

  3. If !no_context || !no_chunks:
       scan_output.export_context(&report, &ExportOptions { ... })
       → ExportSummary { context_files_written, chunk_files_written }

  4. Render output (JSON or text)

  5. If !no_fail && findings > 0 → exit(1)
```

---

## 3. Scan Pipeline (Orchestration)

**File:** `src/scan/mod.rs`

The main orchestrator `scan_repository_with_experimentals()` runs five sequential timed phases:

### Phase Flow

```
1. Config Load  ─→ load_repository_config(&canonical_root)       → RepoConfig
2. Discover     ─→ discover_source_files(root, respect_ignore,    → Vec<PathBuf>
                      supported_extensions)
3. Parse        ─→ analyze_discovered_files(&discovered_files)    → (Vec<ParsedFile>,
                                                                      Vec<ParseFailure>,
                                                                      BTreeMap<Path, Suppressions>)
4. Index        ─→ build_repository_index(&root, &parsed_files)   → RepositoryIndex
5. Evaluate     ─→ evaluate_findings(&parsed_files, &index,       → Vec<Finding>
                      &suppressions, &repo_config, &root, &config)
```

### Assembly (`src/scan/mod.rs:87-106`)

```rust
ScanOutput {
    report: ScanReport {
        root,
        files_discovered: discovered.len(),
        files_analyzed: parsed_files.len(),
        functions_found: parsed_files.iter().map(|f| f.functions.len()).sum(),
        files: file_reports(&parsed_files),
        findings,
        index_summary,
        parse_failures,
        timings: TimingBreakdown { discover_ms, parse_ms, index_ms, heuristics_ms, total_ms },
    },
    parsed_files,  // pub(crate) — used for context export
}
```

### TimingBreakdown (`src/model/scan.rs:14-21`)

```rust
pub struct TimingBreakdown {
    pub discover_ms: u128,
    pub parse_ms: u128,
    pub index_ms: u128,
    pub heuristics_ms: u128,
    pub total_ms: u128,
}
```

---

## 4. File Discovery (Walker)

**File:** `src/scan/walker.rs`

### `discover_source_files()`

Uses the `ignore` crate's `WalkBuilder` — a `.gitignore`-aware directory walker.

```rust
// walker.rs:8-64
pub(crate) fn discover_source_files(
    root: &Path,
    respect_ignore: bool,
    supported_extensions: &[&str],
) -> Vec<PathBuf> {
    let mut walk = WalkBuilder::new(root);
    // If respect_ignore is true: respect hidden, .gitignore, global gitignore
    // If false: disable all
    walk.standard_filters(respect_ignore);
    // ... walk entries, filter to regular files only
    // Filter by supported_extensions (".go", ".py", ".rs")
    // Exclude vendor/ directories
    // Canonicalize paths, reject symlinks outside root
    // Sort and deduplicate
}
```

**Supported extensions** come from `src/analysis/backend.rs:42-54`:

```rust
pub(crate) fn registered_backends() -> &'static [&'static dyn LanguageBackend] { ... }
// Each backend provides: supported_extensions()
// Go → [".go"], Python → [".py"], Rust → [".rs"]
```

---

## 5. File Analysis & Parsing

**File:** `src/scan/file_analysis.rs`

### `analyze_discovered_files()`

Uses **rayon parallel iterator** (`par_iter()`) to process every discovered file.

```rust
// file_analysis.rs:13-44
pub(crate) fn analyze_discovered_files(files: &[PathBuf]) -> (Vec<ParsedFile>,
    Vec<ParseFailure>, BTreeMap<Path, Suppressions>) {
    let outcomes: Vec<FileOutcome> = files.par_iter()
        .map(|path| analyze_file(path))
        .collect();
    // Sort by path, then dispatch into three collections:
    //   - FileOutcome::Parsed { file, suppressions } → ParsedFile + Suppressions
    //   - FileOutcome::Generated → skip
    //   - FileOutcome::Failed { path, error } → ParseFailure
}
```

### `analyze_file()` Per-File Logic (`file_analysis.rs:72-114`)

```
1. Canonicalize path
2. Read file via read_to_string_limited() with DEFAULT_MAX_BYTES (10 MiB)
3. Check if generated → content starts with "Code generated" + "DO NOT EDIT" in first 5 lines
4. Parse suppression directives (deslop-ignore: comments)
5. Resolve language backend: backend_for_path(path)
6. Call analyzer.parse_file(&path, &source) → ParsedFile
```

**Generated file check** (`file_analysis.rs:46-51`):

```rust
fn is_generated(source: &str) -> bool {
    for (i, line) in source.lines().enumerate() {
        if i >= 5 { break; }
        if line.trim().starts_with("Code generated")
            && source.lines().take(5).any(|l| l.contains("DO NOT EDIT"))
        { return true; }
    }
    false
}
```

---

## 6. Language-Specific Parsing

### 6.1 Language Backend Trait (`src/analysis/backend.rs:16-24`)

```rust
pub(crate) trait LanguageBackend: Send + Sync {
    fn language(&self) -> Language;
    fn supported_extensions(&self) -> &'static [&'static str];
    fn supports_path(&self, path: &Path) -> bool;
    fn parse_file(&self, path: &Path, source: &str) -> Result<ParsedFile>;
}
```

Three backends: Go, Python, Rust — each using **tree-sitter** with thread-local parser caching.

### 6.2 Thread-Local Parser Caching

Each language maintains a thread-local parser to avoid re-initializing:

```rust
// Go parser/mod.rs:36-38
thread_local! {
    static GO_PARSER: RefCell<Option<Parser>> = const { RefCell::new(None) };
}
```

Initialization with tree-sitter language grammar:

```rust
parser.set_language(&tree_sitter_go::LANGUAGE.into());   // Go
parser.set_language(&tree_sitter_python::LANGUAGE.into()); // Python
parser.set_language(&tree_sitter_rust::LANGUAGE.into());  // Rust
```

### 6.3 ParsedFile — The Central Output Type (`src/analysis/types/core.rs:24-41`)

```rust
pub(crate) struct ParsedFile {
    pub language: Language,
    pub path: PathBuf,
    pub package_name: Option<String>,
    pub is_test_file: bool,
    pub syntax_error: bool,
    pub line_count: usize,
    pub byte_size: usize,
    pub pkg_strings: Vec<NamedLiteral>,
    pub comments: Vec<CommentSummary>,
    pub functions: Vec<ParsedFunction>,
    pub imports: Vec<ImportSpec>,
    pub symbols: Vec<DeclaredSymbol>,
    pub top_level_bindings: Vec<TopLevelBindingSummary>,
    pub module_scope_calls: Vec<TopLevelCallSummary>,
    pub lang: LanguageFileData,  // Language-specific data
}
```

### 6.4 ParsedFunction (`src/analysis/types/core.rs:156-170`)

```rust
pub(crate) struct ParsedFunction {
    pub fingerprint: FunctionFingerprint,
    pub signature_text: String,
    pub body_start_line: usize,
    pub calls: Vec<CallSite>,
    pub is_test_function: bool,
    pub local_binding_names: Vec<String>,
    pub doc_comment: Option<String>,
    pub body_text: String,
    pub local_strings: Vec<NamedLiteral>,
    pub test_summary: Option<TestFunctionSummary>,
    pub lang: LanguageFunctionData,  // Language-specific evidence
}
```

### 6.5 FunctionFingerprint (`src/model/scan.rs:47-65`)

```rust
pub struct FunctionFingerprint {
    pub name: String,
    pub kind: String,                    // "function" / "method" / "async_function"
    pub receiver_type: Option<String>,
    pub start_line: usize,
    pub end_line: usize,
    pub line_count: usize,
    pub comment_lines: usize,
    pub code_lines: usize,
    pub comment_to_code_ratio: f64,
    pub complexity_score: usize,         // 1 + control flow nodes
    pub symmetry_score: f64,             // repetition of statement kinds
    pub boilerplate_err_guards: usize,   // Go-specific; 0 for Python/Rust
    pub contains_any_type: bool,
    pub contains_empty_interface: bool,
    pub type_assertion_count: usize,
    pub call_count: usize,
}
```

### 6.6 Language Evidence (Owned + View Pattern)

Each language defines evidence structs stored in `LanguageFunctionData`:

```rust
pub(crate) enum LanguageFunctionData {
    Go(GoFunctionEvidence),
    Python(Box<PythonFunctionEvidence>),
    Rust(RustFunctionEvidence),
}
```

Each evidence has an owned struct + a borrowed view type with `empty()` constructor and `as_view()` conversion. Accessor methods on `ParsedFunction`:

```rust
// types/core.rs:182
pub(crate) fn go_evidence(&self) -> GoFunctionEvidenceView<'_> { ... }
pub(crate) fn python_evidence(&self) -> PythonFunctionEvidenceView<'_> { ... }
pub(crate) fn rust_evidence(&self) -> RustFunctionEvidenceView<'_> { ... }
```

#### Go Parsing Extracts

**File-level:** Struct tags, package vars, interfaces, Go structs

**Function-level evidence** (`GoFunctionEvidence`, ~20 fields):
- Context usage, goroutines
- Error handling (dropped errors, panics, errorf calls)
- Loops with allocations, fmt, reflect, concat, JSON
- DB queries, GORM chains
- Parse input calls (JSON/XML/YAML/Proto)
- Gin framework calls

All extracted via tree-sitter AST walking (`go/parser/`, `go/fingerprint.rs`).

#### Python Parsing Extracts

**File-level:** Class summaries, Python models (dataclasses, TypedDicts)

**Function-level evidence** (`PythonFunctionEvidence`, ~40 fields):
- Exception handlers, validation signatures
- Normalized bodies (identifiers → `ID`, strings → `STR`)
- Hotpath patterns: `sorted(x)[0]`, `list(dict.keys())` in loops, `re.compile()` in loops
- Hotpath extensions: invariant calls in loops, `.append()` + `.sort()`, `.index()` in loops
- Performance: string concatenation in loops
- Phase4: None comparisons, side-effect comprehensions, deque candidates, temp collections in loops

Extracted via `python/parser/` with specialized modules: `hotpath.rs`, `hotpath_ext.rs`, `performance.rs`, `phase4.rs`.

#### Rust Parsing Extracts

**File-level:** Statics, enums, structs, attributes, module declarations, includes

**Function-level evidence** (`RustFunctionEvidence`, ~20 fields):
- Safety comments, unsafe lines
- Async points (await, spawn, lock, permit, future creations, select!)
- Blocking calls (filesystem, thread sleep)
- Macro calls (todo!, unimplemented!, dbg!)
- Loop patterns (write, line iteration, default hasher)
- Boxed containers
- Unsafe soundness patterns (get_unchecked, from_raw_parts, set_len, transmute, etc.)

Extracted via `rust/parser/` and analyzed via `rust/evaluate.rs` + `rust/findings/`.

---

## 7. Index Building

**File:** `src/index/build.rs`

### `build_repository_index(root, files)`

Groups `ParsedFile`s into `PackageIndex` entries keyed by `(Language, PackageName, Directory)`.

```rust
pub(crate) struct PackageIndex {
    pub functions: BTreeSet<String>,
    pub contextless_wrapper_functions: BTreeSet<String>,
    pub methods_by_receiver: BTreeMap<String, BTreeSet<String>>,
    pub symbols: Vec<IndexedSymbol>,
    pub import_count: usize,
}
```

### RepositoryIndex (`src/index/mod.rs:40-49`)

- Maps `PackageKey` → `PackageIndex`
- Rust-specific: module hierarchy, crate roots, include neighbors

### Import Resolution (`src/index/resolve.rs`)

Three-layer resolution for Rust:
1. Module graph (`crate::`, `self::`, `super::`)
2. Legacy file-system layout
3. Package matching (suffix-based)

For Go/Python: matches directory suffix against import paths.

---

## 8. Rule Evaluation (Heuristics Engine)

**File:** `src/heuristics/engine.rs`

### Entry Points

```rust
// engine.rs:11-33
pub(crate) fn evaluate_file(
    file: &ParsedFile, index: &RepositoryIndex, config: &AnalysisConfig,
) -> Vec<Finding> {
    let mut findings = evaluate_file_specs(shared_rule_specs(), file, index, config);
    findings.extend(evaluate_file_specs(language_rule_specs(file.language), file, index, config));
    findings
}

pub(crate) fn evaluate_repo(
    language: Language, files: &[&ParsedFile], index: &RepositoryIndex, config: &AnalysisConfig,
) -> Vec<Finding> {
    evaluate_repo_specs(language_rule_specs(language), files, index, config)
}
```

### Rule Execution Specs (`src/heuristics/registry.rs:48-60`)

```rust
pub(crate) struct RuleExecutionSpec {
    pub(crate) family: &'static str,
    pub(crate) file_rules: &'static [FileRule],
    pub(crate) indexed_file_rules: &'static [IndexedFileRule],
    pub(crate) optional_function_rules: &'static [OptionalFunctionRule],
    pub(crate) function_rules: &'static [FunctionRule],
    pub(crate) file_function_rules: &'static [FileFunctionRule],
    pub(crate) indexed_function_rules: &'static [IndexedFunctionRule],
    pub(crate) configurable_function_rules: &'static [ConfigurableFunctionRule],
    pub(crate) repo_rules: &'static [RepoRule],
    pub(crate) indexed_repo_rules: &'static [IndexedRepoRule],
    pub(crate) configurable_enabled: fn(&AnalysisConfig) -> bool,
}
```

### Rule Function Type Aliases (`registry.rs:37-46`)

```rust
pub(crate) type FileRule = fn(&ParsedFile) -> Vec<Finding>;
pub(crate) type IndexedFileRule = fn(&ParsedFile, &RepositoryIndex) -> Vec<Finding>;
pub(crate) type FunctionRule = fn(&ParsedFile, &ParsedFunction) -> Vec<Finding>;
pub(crate) type OptionalFunctionRule = fn(&ParsedFile, &ParsedFunction) -> Option<Finding>;
pub(crate) type IndexedFunctionRule = fn(&ParsedFile, &ParsedFunction, &RepositoryIndex) -> Vec<Finding>;
pub(crate) type FileFunctionRule = fn(&ParsedFile, &ParsedFunction, &[ImportSpec]) -> Vec<Finding>;
pub(crate) type ConfigurableFunctionRule = fn(&ParsedFile, &ParsedFunction, bool) -> Vec<Finding>;
pub(crate) type RepoRule = fn(&[&ParsedFile]) -> Vec<Finding>;
pub(crate) type IndexedRepoRule = fn(&[&ParsedFile], &RepositoryIndex) -> Vec<Finding>;
```

### Core Evaluation Loop (`engine.rs:35-81`)

```
evaluate_file_specs(specs, file, index, config):
  For each RuleExecutionSpec:
    1. Run file_rules      → extend_file_rules()      — whole file
    2. Run indexed_file_rules → extend_indexed_file_rules() — file + index
    3. For each function in file.functions:
       a. optional_function_rules → extend_optional_function_rules() → Option<Finding>
       b. function_rules          → extend_function_rules()         → Vec<Finding>
       c. file_function_rules     → extend_file_function_rules()    → function + imports
       d. indexed_function_rules  → extend_indexed_function_rules() → function + index
       e. configurable_function_rules → extend_configurable_function_rules() → function + bool
```

### Evaluate Findings (Post-Processing) (`src/scan/evaluate.rs:17-61`)

```
evaluate_findings():
  1. Per-file evaluation (rayon parallel):
       files.par_iter().flat_map(|file| evaluate_file(file, index, config))

  2. Per-repo evaluation:
       For each backend: evaluate_repo(language, files, index, config)

  3. Suppression filtering:
       findings.retain(|f| !is_suppressed(f, suppressions))  // deslop-ignore:

  4. Registry defaults:
       apply_registry_defaults()  // set severity from rule registry

  5. Repository config:
       apply_repository_config()  // disabled_rules, suppressed_paths, severity_overrides

  6. Fixture coverage expectations:
       apply_rule_fixture_coverage_expectations()  // internal test fixtures

  7. Sort by (path, start_line, rule_id), dedup
```

### Shared Rules (`SHARED_RULE_SPECS`, `registry.rs:70-136`)

| Family | Rule Functions | Granularity |
|--------|---------------|-------------|
| `security` | `pkg_secret_findings` (file), `secret_findings` (function) | File + Function |
| `naming` | `generic_finding`, `overlong_finding`, `weak_finding` | Optional Function |
| `comments` | `comment_findings` | Function |
| `test_quality` | `test_findings` | Function |
| `hallucination` | `hallucination_findings` | Indexed Function |

### Go Rules (`GO_RULE_SPECS`, 13 families)

| Family | Description |
|--------|-------------|
| `architecture` | Go architecture patterns (file + repo rules) |
| `idioms` | Go idioms (`go_file_findings`, `go_repo_findings`) |
| `consistency` | Tag conventions, receiver naming |
| `style` | Import grouping, package name consistency |
| `errors` | Error handling patterns |
| `context` | Context propagation, cancellation |
| `concurrency` | Goroutines, mutexes, waitgroups |
| `performance` | Allocation, crypto, SQL, fmt, reflect, concat, JSON, load, N+1, DB |
| `framework_patterns` | Gin, GORM, data access |
| `library_misuse` | Stdlib misuse patterns |

### Python Rules (Family: `python_specs`)

Uses a **two-level spec system**:
- `python/mod.rs` → `python_findings`, `python_file_findings`, `python_repo_findings`
- `python/specs/runtime.rs` → `evaluate_function_specs(FUNCTION_RULE_SPECS, ...)`
- `python/specs/catalog.rs` → `FUNCTION_RULE_SPECS` array of `PythonFunctionRuleSpec`

Each spec has a `family`, `rule_ids` list, and `evaluate` function pointer. Families include:
quality, performance, maintainability, structure, ai_smells, hot_path, hot_path_ext, framework, mlops, packaging, architecture, discipline, boundaries, observability.

### Rust Rules (`RUST_RULE_SPECS`, 15 families)

| Family | Description |
|--------|-------------|
| `hygiene` | Eval, doc markers, unwrap/expect, unsafe |
| `api_design` | API surface rules |
| `async_patterns` | Async/await patterns |
| `domain_modeling` | Domain modeling |
| `performance` | Performance issues |
| `runtime_boundary` | Runtime boundary crossings |
| `unsafe_soundness` | Unsafe code correctness |
| `boundary` | Module boundary violations |
| `module_surface` | Module surface area |
| `runtime_ownership` | Ownership patterns |
| `security_footguns` | Security vulnerabilities |
| `bad_practices` | Bad practices |
| `resolution` | Import resolution / local call verification |

### Performance Layers System (`src/heuristics/performance_layers.rs`)

A unique subsystem that dynamically compiles rules from the catalog:

1. Reads all rules from `rule_registry()` with language-specific prefixes (`go_perf_layer_`, `python_perf_layer_`, `rust_perf_layer_`)
2. Compiles each rule ID into a `CompiledPerfLayerRule`:
   - Parses rule ID suffix → category + tokens
   - Language-specific token markers and category markers
3. Flags: `REQUIRE_LOOP`, `REQUIRE_NESTED_LOOP`, `REQUIRE_ASYNC_SIGNAL`, `REQUIRE_HOT_PATH`
4. Negative markers for exclusions
5. Matches by checking if function body (lowercased) contains marker strings

---

## 9. Finding Model

### Core Finding Type (`src/model/scan.rs:67-77`)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,              // e.g. "go_function_too_long"
    pub severity: Severity,           // Info | Warning | Error
    pub path: PathBuf,                // source file path
    pub function_name: Option<String>, // if scoped to a function
    pub start_line: usize,
    pub end_line: usize,
    pub message: String,              // human-readable description
    pub evidence: Vec<String>,        // lines of source evidence
}
```

### Severity (`src/model/scan.rs:23-29`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}
```

### How a Rule Produces a Finding

**Example 1: `OptionalFunctionRule`** — from `naming.rs`:

```rust
pub(super) fn overlong_finding(
    file: &ParsedFile, function: &ParsedFunction,
) -> Option<Finding> {
    if function.is_test_function { return None; }
    if function.fingerprint.name.len() < 28 { return None; }

    Some(Finding {
        rule_id: "overlong_name".to_string(),
        severity: Severity::Info,
        path: file.path.clone(),
        function_name: Some(function.fingerprint.name.clone()),
        start_line: function.fingerprint.start_line,
        end_line: function.fingerprint.end_line,
        message: format!("function {} uses an overly descriptive name",
            function.fingerprint.name),
        evidence: vec![function.fingerprint.name.clone()],
    })
}
```

**Example 2: `FunctionRule`** — from `security.rs`:

```rust
pub(super) fn crypto_findings(
    file: &ParsedFile, function: &ParsedFunction,
) -> Vec<Finding> {
    let import_aliases = import_alias_lookup(&file.imports);
    let mut findings = Vec::new();

    for call in &function.calls {
        let Some(receiver) = &call.receiver else { continue };
        let Some(import_path) = import_aliases.get(receiver) else { continue };
        if !WEAK_CRYPTO_IMPORTS.contains(&import_path.as_str()) { continue }

        findings.push(Finding {
            rule_id: "weak_crypto".to_string(),
            severity: Severity::Warning,
            path: file.path.clone(),
            function_name: Some(function.fingerprint.name.clone()),
            start_line: call.line,
            end_line: call.line,
            message: format!("function {} uses weak cryptographic primitive {}",
                function.fingerprint.name, import_path),
            evidence: vec![/* call details */],
        });
    }
    findings
}
```

### ScanReport (`src/model/scan.rs:102-113`)

```rust
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub root: PathBuf,
    pub files_discovered: usize,
    pub files_analyzed: usize,
    pub functions_found: usize,
    pub files: Vec<FileReport>,
    pub findings: Vec<Finding>,
    pub index_summary: IndexSummary,
    pub parse_failures: Vec<ParseFailure>,
    pub timings: TimingBreakdown,
}
```

### ScanOutput (`src/model/scan.rs:96-100`)

```rust
#[derive(Debug, Clone)]
pub struct ScanOutput {
    pub report: ScanReport,
    pub(crate) parsed_files: Vec<analysis::ParsedFile>,  // for export
}
```

---

## 10. Export: Context & Chunk Generation

### 10.1 Entry Point (`src/export/mod.rs:13-21`)

```rust
impl ScanOutput {
    pub fn export_context(
        &self, report: &ScanReport, options: &ExportOptions,
    ) -> Result<ExportSummary> {
        export_finding_context(report, &self.parsed_files, options)
    }
}
```

### 10.2 Main Export Function (`src/export/writer.rs:27-73`)

```rust
pub fn export_finding_context(
    report: &ScanReport,
    parsed_files: &[ParsedFile],
    options: &ExportOptions,
) -> Result<ExportSummary> {
    // Early return if neither requested
    if !options.export_context && !options.export_chunks {
        return Ok(ExportSummary::default());
    }

    let findings = visible_findings(report, options.details);
    if findings.is_empty() {
        return Ok(ExportSummary::default());
    }

    // Build ALL FindingBlocks first (resolves function context for every finding)
    let mut cached_lines = HashMap::new();
    let blocks: Vec<FindingBlock> = findings.iter().enumerate()
        .map(|(index, finding)| {
            build_finding_block(finding, report, parsed_files,
                                &mut cached_lines, index + 1, findings.len(), options.details)
        })
        .collect();

    let mut summary = ExportSummary::default();
    if options.export_context {
        summary.context_files_written =
            write_context_files(&blocks, &options.context_output_dir)?;
    }
    if options.export_chunks {
        summary.chunk_files_written =
            write_chunk_files(&blocks, &options.chunks_output_dir,
                              options.chunk_size.max(1))?;
    }
    Ok(summary)
}
```

### 10.3 Context File Writing (`src/export/writer.rs:75-85`)

```rust
fn write_context_files(blocks: &[FindingBlock], output_dir: &Path) -> Result<usize> {
    fs::create_dir_all(output_dir)?;
    clean_txt_files(output_dir)?;  // Remove prior *.txt

    for (index, block) in blocks.iter().enumerate() {
        let output_path = output_dir.join(format!("{}.txt", index + 1));
        fs::write(&output_path, &block.text)?;
    }
    Ok(blocks.len())
}
```

**Output structure** (default: `scripts/findings/functions/`):
```
scripts/findings/functions/
  1.txt
  2.txt
  ...
  N.txt
```

### 10.4 Chunk File Writing (`src/export/writer.rs:87-109`)

```rust
fn write_chunk_files(
    blocks: &[FindingBlock], output_dir: &Path, chunk_size: usize,
) -> Result<usize> {
    fs::create_dir_all(output_dir)?;
    clean_chunk_files(output_dir)?;  // Remove prior Chunk_*.txt

    let separator = block_separator();  // "=" x 100
    let total = blocks.len();
    let mut chunk_count = 0;

    for (chunk_idx, chunk) in blocks.chunks(chunk_size).enumerate() {
        let start_index = chunk_idx * chunk_size + 1;          // 1-based
        let end_index = start_index + chunk.len() - 1;
        let content = build_chunk_content(chunk, start_index, end_index, total, separator);
        let output_path = chunk_output_path(output_dir, start_index, end_index);
        fs::write(&output_path, content)?;
        chunk_count += 1;
    }
    Ok(chunk_count)
}
```

**Output structure** (default: `scripts/chunks/`):
```
scripts/chunks/
  Chunk_1_25.txt
  Chunk_26_50.txt
  Chunk_51_75.txt
  ...
```

### 10.5 Chunk Content Assembly (`src/export/chunk.rs:5-26`)

```rust
pub(crate) fn build_chunk_content(
    blocks: &[FindingBlock], start_index: usize, end_index: usize,
    total: usize, separator: &str,
) -> String {
    let mut parts = vec![
        format!("Findings {start_index}-{end_index} of {total}"),
        String::new(),  // blank line
    ];

    for (offset, block) in blocks.iter().enumerate() {
        if offset > 0 {
            parts.push(separator.to_string());
            parts.push(String::new());
        }
        parts.push(block.text.trim_end().to_string());
    }

    format!("{}\n", parts.join("\n"))
}
```

**Chunk file output format:**
```
Findings 1-25 of 100

Finding 1/100
Source: path/to/file.go:42
Rule: [some_rule_id]
Rule description: ...
Auto triage note: ...
Function:
    fn some_func() {
        ...
    }

====================================================================================================

Finding 2/100
...
```

### 10.6 Chunk File Naming (`src/export/chunk.rs:28-38`)

```rust
pub(crate) fn chunk_filename(start_index: usize, end_index: usize) -> String {
    format!("Chunk_{start_index}_{end_index}.txt")
}
```

### 10.7 FindingBlock Structure (`src/export/block.rs:14-16`)

```rust
pub(crate) struct FindingBlock {
    pub text: String,
}
```

### 10.8 Finding Block Assembly (`src/export/block.rs:18-100`)

`build_finding_block()` builds text for each finding:

**Detailed mode** (lines 49-74):
- Header: `"Finding {index}/{total}"`
- Source: `"Source: {}:{}"` (path:line)
- Rule metadata: ID, status, category, go relevance, description
- Message
- Function range: `"[{start}-{end}]"`
- Auto triage label + note
- `"False positive: [REVIEW_NEEDED]"`
- Original finding line
- Function source code (4-space indented)

**Compact mode** (lines 75-83):
- Source, rule ID, description, triage note, function source

### 10.9 Function Context Resolution (`src/export/function.rs:15-64`)

Three-stage lookup:

```rust
pub(crate) fn resolve_function_context(
    finding: &Finding,
    parsed_files: &[ParsedFile],
    cached_lines: &mut HashMap<PathBuf, Vec<String>>,
) -> FunctionContext {
    // STAGE 1: AST-based — find enclosing function from ParsedFile.functions
    if let Some(parsed_file) = parsed_files.iter().find(|f| f.path == finding.path)
        && let Some(function) = find_enclosing_function(parsed_file,
            finding.start_line, finding.function_name.as_deref())
    {
        let lines = load_source_lines(&finding.path, cached_lines);
        let function_lines = slice_lines(&lines, function.fingerprint.start_line,
                                          function.fingerprint.end_line);
        if !function_lines.is_empty() {
            return FunctionContext {
                start_line: function.fingerprint.start_line,
                end_line: function.fingerprint.end_line,
                lines: function_lines,
            };
        }
    }

    // STAGE 2: Heuristic — brace-matching (Go/Rust) or indentation (Python)
    let lines = load_source_lines(&finding.path, cached_lines);
    if let Some((start_line, end_line, function_lines)) =
        extract_enclosing_function(&lines, &finding.path, finding.start_line)
    {
        return FunctionContext { start_line, end_line, lines: function_lines };
    }

    // STAGE 3: Fallback — empty context at finding's line
    FunctionContext { start_line: finding.start_line, end_line: finding.start_line, lines: vec![] }
}
```

### 10.10 AST-Based Function Lookup (`src/export/function.rs:66-83`)

```rust
fn find_enclosing_function<'a>(
    file: &'a ParsedFile, line_no: usize, function_name: Option<&str>,
) -> Option<&'a ParsedFunction> {
    file.functions.iter()
        .find(|f| f.fingerprint.start_line <= line_no && line_no <= f.fingerprint.end_line)
        .or_else(|| function_name.and_then(|name| {
            file.functions.iter().find(|f| f.fingerprint.name == name)
        }))
}
```

### 10.11 Heuristic Function Extraction (`src/export/function.rs:104-225`)

**Python** (`extract_python_function`, lines 134-169):
- Scan backward for `def ` or `async def `
- Capture decorators (`@`)
- Determine extent by tracking indentation level

**Brace-based** (`extract_brace_function`, lines 171-225):
- For Go/Rust: scan backward for `fn ` / `func `
- Find opening `{`, brace-match to closing `}`
- Capture leading attributes (`#[...]`, `///`, `//`)

### 10.12 Source Line Caching (`src/export/function.rs:85-95`)

```rust
fn load_source_lines(path: &Path, cache: &mut HashMap<PathBuf, Vec<String>>) -> Vec<String> {
    if let Some(lines) = cache.get(path) { return lines.clone(); }
    let lines: Vec<String> = read_to_string_limited(path, DEFAULT_MAX_BYTES)
        .map(|c| c.lines().map(str::to_string).collect())
        .unwrap_or_default();
    cache.insert(path.to_path_buf(), lines.clone());
    lines
}
```

### 10.13 Auto-Triage (`src/export/triage.rs:54-98`)

`triage_finding()` classifies each finding using:
- **Context text**: function source (lowercased), 25 lines before finding + 5 lines after
- **Current line**: specific line of the finding
- **Rule metadata** from the registry

Returns one of:

| Label | Description |
|-------|-------------|
| `LIKELY_FALSE_POSITIVE` | Known false positive patterns (e.g., cgo with "caller must free") |
| `LIKELY_SUBJECTIVE` | Naming, style, duplication, maintainability, or info-level rules |
| `CONTEXT_DEPENDENT` | Async patterns, concurrency, performance, contextual-severity rules |
| `LIKELY_REAL` | Errors, security, warning/error severity rules |
| `REVIEW_NEEDED` | Fallback — no metadata available |

### 10.14 TriageResult and FunctionContext

```rust
// function.rs:9-13
pub(crate) struct FunctionContext {
    pub start_line: usize,
    pub end_line: usize,
    pub lines: Vec<String>,
}

// triage.rs:49-52
pub(crate) struct TriageResult {
    pub label: &'static str,  // "LIKELY_REAL", "CONTEXT_DEPENDENT", etc.
    pub note: String,
}
```

### 10.15 Cleanup Functions (`src/export/writer.rs:111-146`)

```rust
fn clean_txt_files(output_dir: &Path) -> Result<()> {
    for entry in fs::read_dir(output_dir)? {
        let path = entry?.path();
        if path.is_file()
            && path.extension().is_some_and(|ext| ext == "txt")
        {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

fn clean_chunk_files(output_dir: &Path) -> Result<()> {
    for entry in fs::read_dir(output_dir)? {
        let path = entry?.path();
        if path.is_file()
            && path.file_name().and_then(|n| n.to_str())
                .is_some_and(|name| name.starts_with("Chunk_") && name.ends_with(".txt"))
        {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}
```

---

## 11. Report Formatting

### 11.1 Human-Readable Scan Report (`src/cli/report.rs:11-126`)

```
deslop scan root: /path/to/repo
Source files discovered: 42
Source files analyzed: 40
Functions fingerprinted: 320
Findings: 5
Index summary: packages=3 symbols=15 imports=8
Parse failures: 1
Timings: discover=12ms parse=145ms index=30ms heuristics=22ms total=209ms

Findings:
  - src/main.go:42 function Run loads entire payload [full_dataset_load / performance / stable]
  - src/utils.go:15 ...
```

In `--details` mode, per-file function listings are also printed.

### 11.2 JSON Scan Report (`src/cli/report.rs:133-144`)

```rust
pub(crate) fn format_scan_report_json(
    report: &deslop::ScanReport, details: bool,
) -> Result<String> {
    if details {
        Ok(serde_json::to_string_pretty(report)?)       // Full serialization
    } else {
        Ok(serde_json::to_string_pretty(&ScanReportSummary::from(report))?)  // Filtered
    }
}
```

The `ScanReportSummary` trims function fingerprints (removes byte_size, comment_lines, code_lines, line_count, complexity_score, symmetry_score, etc.) and enriches each finding with rule metadata.

### 11.3 Rules Report

Text format (`src/cli/rules.rs`):
```
deslop rules: 175 matching rule entries
filters: language=go status=<all-statuses>
by status: draft=93, incomplete=77, stable=5
- CWE-89 [Injection / Stable / High]
  Improper neutralization of special elements used in an SQL command
```

JSON format: serializes the filtered Go ruleset entries.

---

## 12. Key Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            main.rs (clap parse)                          │
│                    --chunk-size 25 --chunks-output-dir scripts/chunks     │
│           --context-output-dir scripts/findings/functions                 │
└──────────────────────────┬───────────────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     cli::execute_scan(ScanCommandOptions)                │
│  1. scan_repository_with_experimentals()                                 │
│  2. Filter by --ignore list                                              │
│  3. export_context() → ExportSummary                                     │
│  4. format_scan_report() → stdout                                        │
└──────────────────────────┬───────────────────────────────────────────────┘
                           │
            ┌──────────────┴──────────────┐
            ▼                             ▼
┌──────────────────────┐    ┌──────────────────────────────┐
│   scan/ (orchestrate) │    │  export/ (context & chunks)  │
│   1. Config load      │    │  export_finding_context():   │
│   2. discover_source() │    │  1. visible_findings()      │
│   3. analyze_files()  │    │  2. For each finding:        │
│   4. build_index()    │    │     build_finding_block()    │
│   5. evaluate()       │    │     ├─ resolve_function()    │
│   6. assemble report  │    │     ├─ triage_finding()      │
└──────────┬───────────┘    │     └─ format block text     │
           │                │  3. write_context_files()     │
           ▼                │     → scripts/findings/funcs/ │
┌──────────────────────┐    │  4. write_chunk_files()       │
│  heuristics/engine   │    │     → scripts/chunks/        │
│  evaluate_file():     │    └──────────────────────────────┘
│  ┌ shared rules      │
│  └ language rules    │
│                      │
│  evaluate_repo():    │
│  ┌ cross-file rules  │
└──────────────────────┘
           ▲
           │
┌──────────┴───────────┐
│  analysis/ (parsing)  │
│  backend_for_path()   │
│  ┌ Go (tree-sitter)   │
│  ├ Python (tree-sitter)│
│  └ Rust (tree-sitter) │
│       → ParsedFile     │
└────────────────────────┘
```

---

## 13. Appendix: Directory Structure

```
src/
├── main.rs                    # CLI entry point (clap-based)
├── lib.rs                     # Library facade, re-exports
├── error.rs                   # Unified error types (thiserror)
├── io.rs                      # File I/O (symlink-safe reads, byte limits)
├── config.rs                  # .deslop.toml parsing
├── rules.rs                   # Rule registry, metadata, catalog
│   └── catalog/               # Rule definition catalog
├── model/                     # Core data types
│   ├── scan.rs                # Finding, ScanReport, ScanOutput, Severity, etc.
│   └── benchmark.rs           # BenchmarkReport, StageStats, BenchmarkRun
├── cli/                       # CLI dispatchers and formatting
│   ├── mod.rs                 # execute_scan, execute_bench, execute_rules
│   ├── report.rs              # Scan report formatting (text + JSON)
│   └── rules.rs               # Rules listing (text + JSON)
├── scan/                      # Scan orchestration
│   ├── mod.rs                 # Pipeline orchestration (5 phases)
│   ├── walker.rs              # Repository file discovery
│   ├── file_analysis.rs        # Parallel file parsing
│   ├── evaluate.rs            # Rule evaluation post-processing
│   ├── reporting.rs           # File report assembly
│   ├── suppression.rs         # Suppression directive parsing
│   └── tests.rs               # Unit tests
├── analysis/                  # Language-specific parsing
│   ├── mod.rs                 # Facade
│   ├── backend.rs             # Language enum, LanguageBackend trait
│   ├── error.rs               # Analysis errors
│   ├── config.rs              # AnalysisConfig
│   ├── types/                 # Shared + language-specific types
│   │   ├── core.rs            # ParsedFile, ParsedFunction
│   │   ├── common.rs          # CommentSummary, CallSite, ImportSpec, etc.
│   │   ├── go.rs              # GoFunctionEvidence, GoFileData
│   │   ├── python.rs          # PythonFunctionEvidence, PythonFileData
│   │   └── rust.rs            # RustFunctionEvidence, RustFileData
│   ├── go/                    # Go parser
│   ├── python/                # Python parser
│   └── rust/                  # Rust parser
├── heuristics/                # Rule execution engine
│   ├── mod.rs                 # Module declarations
│   ├── engine.rs              # evaluate_file, evaluate_repo
│   ├── registry.rs            # Rule execution specs + type aliases
│   ├── common.rs              # Shared utilities (name parsing, alias lookup)
│   ├── naming.rs              # Naming heuristics
│   ├── security.rs            # Security heuristics
│   ├── comments.rs            # Comment quality heuristics
│   ├── test_quality.rs        # Test quality heuristics
│   ├── hallucination.rs       # Cross-reference hallucination detection
│   ├── performance_layers.rs  # Dynamic perf layer rule engine
│   ├── performance_layers/    # Generated perf layer tests
│   ├── go/                    # Go-specific rules (12 families)
│   ├── python/                # Python-specific rules
│   └── rust/                  # Rust-specific rules (15 families)
├── export/                    # Context & chunk export
│   ├── mod.rs                 # ScanOutput::export_context()
│   ├── writer.rs              # ExportOptions, ExportSummary, file writing
│   ├── block.rs               # FindingBlock builder
│   ├── chunk.rs               # Chunk content assembly
│   ├── function.rs            # Function context resolution
│   └── triage.rs              # Auto-triage classification
└── index/                     # Repository indexing
    ├── mod.rs                 # RepositoryIndex, PackageIndex
    ├── build.rs               # Index construction
    ├── resolve.rs             # Import resolution
    └── tests.rs               # Index tests
```

---

## Quick Reference: Key Defaults

| Setting | Default | CLI Flag |
|---------|---------|----------|
| Chunk size | 25 findings per file | `--chunk-size <N>` |
| Context output dir | `scripts/findings/functions` | `--context-output-dir <dir>` |
| Chunks output dir | `scripts/chunks` | `--chunks-output-dir <dir>` |
| Max file size | 10 MiB | (hardcoded `DEFAULT_MAX_BYTES`) |
| Supported extensions | `.go`, `.py`, `.rs` | (hardcoded in backends) |
| Parallelism | rayon (automatic) | N/A |
