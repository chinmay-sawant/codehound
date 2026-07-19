//! Taint-analysis data model: kinds, nodes, edges, scopes, annotations, call graph.

use std::collections::HashMap;
use std::ops::Range;
use std::sync::Arc;

pub type TaintNodeId = usize;
pub type ScopeId = usize;
pub type SharedText = Arc<str>;

/// Classification of a taint source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SourceKind {
    /// HTTP request fields: `r.URL.Query`, `r.FormValue`, `r.PostForm`, ...
    UserInput,
    /// CLI arguments: `os.Args`, `flag.Args`, `flag.String`.
    Args,
    /// Environment variables: `os.Getenv`, `os.LookupEnv`.
    EnvVar,
    /// File reads: `os.ReadFile`, `ioutil.ReadFile`, `os.Open`, `io.ReadAll`, ...
    File,
    /// Network reads: `net.Conn.Read`, `http.Request.Body`.
    Network,
}

/// Classification of a taint sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SinkKind {
    /// Command execution: `exec.Command`, `(*Cmd).Run/Start/Output`.
    CommandExec,
    /// SQL execution: `(*sql.DB).Query/Exec`, `(*sql.Tx).Query/Exec`, ...
    SQLQuery,
    /// File creation/opening: `os.Create`, `os.OpenFile`, `os.WriteFile`.
    FileOpen,
    /// Template execution: `(*template.Template).Execute/ExecuteTemplate`.
    Template,
    /// HTTP response writes.
    HTTPWrite,
    /// Deserialization: `json.Unmarshal`, `xml.Unmarshal`, `gob.NewDecoder`.
    Deserialization,
    /// LDAP queries: `ldap.Dial`, `ldap.Search`, `ldap.SearchByAttribute`, `ldap.NewSearchRequest`.
    LDAPQuery,
    /// XML queries / unmarshalling: `xml.Unmarshal`, `(*Decoder).Decode`, `(*Decoder).DecodeElement`.
    XMLQuery,
}

/// Classification of a sanitizer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SanitizerKind {
    /// Path cleaning: `filepath.Clean`, `path.Clean`.
    Path,
    /// HTML escaping: `html.EscapeString`, `template.HTMLEscaper`, ...
    HTML,
    /// URL escaping: `url.QueryEscape`, `url.PathEscape`.
    URL,
    /// SQL prepared statement: `(*sql.DB).Prepare` followed by `(*sql.Stmt).Exec/Query`.
    SQL,
    /// Regular-expression validation used as a guard.
    Validation,
    /// Bounded slicing: `len(...) < N` then `s[:N]`.
    Bounded,
    /// LDAP escaping: `ldap.EscapeFilter`.
    LDAP,
    /// XML escaping: `xml.EscapeText`.
    XML,
}

/// One node in the taint graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintNode {
    /// A function call that produces tainted data.
    Source {
        function: SharedText,
        kind: SourceKind,
        byte_range: Range<usize>,
    },
    /// A variable in scope.
    Variable {
        name: SharedText,
        type_hint: Option<SharedText>,
        scope: ScopeId,
        decl_byte: usize,
    },
    /// A function call that consumes tainted data.
    Sink {
        function: SharedText,
        kind: SinkKind,
        argument_index: usize,
        byte_range: Range<usize>,
    },
    /// A function call that produces a sanitized value.
    Sanitizer {
        function: SharedText,
        kind: SanitizerKind,
        byte_range: Range<usize>,
    },
    /// A function return value.
    Return { function: SharedText, index: usize },
}

impl TaintNode {
    pub fn byte_range(&self) -> Option<Range<usize>> {
        match self {
            TaintNode::Source { byte_range, .. }
            | TaintNode::Sink { byte_range, .. }
            | TaintNode::Sanitizer { byte_range, .. } => Some(byte_range.clone()),
            TaintNode::Variable { decl_byte, .. } => Some(*decl_byte..*decl_byte),
            TaintNode::Return { .. } => None,
        }
    }
}

/// Edge semantics in the taint graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EdgeKind {
    /// `lhs = rhs` or `lhs := rhs`.
    Assignment,
    /// Argument passed to a sink, sanitizer, or helper.
    Argument(usize),
    /// Data returned from a call.
    Return,
    /// Data flows through a function without modification.
    PassThrough,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintEdge {
    pub from: TaintNodeId,
    pub to: TaintNodeId,
    pub kind: EdgeKind,
}

/// The taint graph for a single compilation unit.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TaintGraph {
    pub nodes: Vec<TaintNode>,
    pub edges: Vec<TaintEdge>,
    /// Variable name -> node ids, scoped by `ScopeId`.
    pub by_variable: HashMap<(ScopeId, SharedText), Vec<TaintNodeId>>,
    pub by_sink: HashMap<SinkKind, Vec<TaintNodeId>>,
    pub by_source: HashMap<SourceKind, Vec<TaintNodeId>>,
}

impl TaintGraph {
    /// Return all graph nodes in insertion order.
    pub fn nodes(&self) -> &[TaintNode] {
        &self.nodes
    }

    /// Return all graph edges in insertion order.
    pub fn edges(&self) -> &[TaintEdge] {
        &self.edges
    }

    /// Return variable-to-node adjacency indexes.
    pub fn variables(&self) -> &HashMap<(ScopeId, SharedText), Vec<TaintNodeId>> {
        &self.by_variable
    }

    /// Return sink-kind-to-node adjacency indexes.
    pub fn sinks(&self) -> &HashMap<SinkKind, Vec<TaintNodeId>> {
        &self.by_sink
    }

    /// Return source-kind-to-node adjacency indexes.
    pub fn sources(&self) -> &HashMap<SourceKind, Vec<TaintNodeId>> {
        &self.by_source
    }

    pub fn add_node(&mut self, node: TaintNode) -> TaintNodeId {
        let id = self.nodes.len();
        if let TaintNode::Variable { scope, name, .. } = &node {
            self.by_variable
                .entry((*scope, Arc::clone(name)))
                .or_default()
                .push(id);
        }
        if let TaintNode::Source { kind, .. } = &node {
            self.by_source.entry(*kind).or_default().push(id);
        }
        if let TaintNode::Sink { kind, .. } = &node {
            self.by_sink.entry(*kind).or_default().push(id);
        }
        self.nodes.push(node);
        id
    }

    pub fn add_edge(&mut self, from: TaintNodeId, to: TaintNodeId, kind: EdgeKind) {
        self.edges.push(TaintEdge { from, to, kind });
    }
}

/// Scope metadata for intra-procedural variable resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeInfo {
    pub id: ScopeId,
    pub parent: Option<ScopeId>,
    pub kind: ScopeKind,
    /// Byte range of the scope in the source file.
    pub byte_range: Range<usize>,
    /// Function this scope belongs to, if known.
    pub function: Option<SharedText>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScopeKind {
    /// File/package-level scope used for declarations outside functions.
    Package,
    Function,
    Block,
    If,
    For,
    Switch,
    Case,
}

/// Raw annotations extracted from a single `ParsedUnit`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TaintAnnotations {
    pub sources: Vec<TaintSourceAnnotation>,
    pub sinks: Vec<TaintSinkAnnotation>,
    pub sanitizers: Vec<TaintSanitizerAnnotation>,
    pub assignments: Vec<AssignmentDetail>,
    pub scopes: Vec<ScopeInfo>,
    /// Function name → parameter names, for computing TaintSummary.
    pub function_params: HashMap<SharedText, Vec<SharedText>>,
    /// Function name → byte range of the function declaration.
    pub function_ranges: HashMap<SharedText, Range<usize>>,
    /// Sites where taint flow is intentionally not modeled (channels, goroutines).
    pub unsupported_flows: Vec<UnsupportedFlow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSourceAnnotation {
    pub function: SharedText,
    pub kind: SourceKind,
    pub byte_range: Range<usize>,
    pub result_variable: Option<SharedText>,
    pub arguments: Box<[SharedText]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSinkAnnotation {
    pub function: SharedText,
    pub kind: SinkKind,
    pub argument_index: usize,
    pub argument_text: SharedText,
    /// All positional argument texts, used when the sink is multi-argument
    /// and any argument may carry taint (e.g. `exec.Command`).
    pub all_arguments: Box<[SharedText]>,
    pub byte_range: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSanitizerAnnotation {
    pub function: SharedText,
    pub kind: SanitizerKind,
    pub byte_range: Range<usize>,
    pub result_variable: Option<SharedText>,
    pub arguments: Box<[SharedText]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentDetail {
    pub lhs: SharedText,
    pub rhs_text: SharedText,
    pub scope: ScopeId,
    pub byte_range: Range<usize>,
    /// True when the RHS is a direct source or sanitizer call; identifier
    /// references inside it should not create extra assignment edges.
    pub from_source_or_sanitizer: bool,
    /// True when this is a channel send (`ch <- v`). Treated as **unsupported**
    /// for taint flow (explicit FN) — not modeled as a normal assignment.
    pub is_channel_send: bool,
}

/// Record of an unsupported taint flow site (channels, goroutine handoff).
/// Used for honest FNs and diagnostics — not for graph edges that pretend to work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedFlow {
    pub kind: UnsupportedFlowKind,
    pub byte_range: Range<usize>,
    pub note: SharedText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum UnsupportedFlowKind {
    /// `ch <- value` or receive forms — taint does not cross channels.
    Channel,
    /// `go f(...)` — taint does not track into spawned goroutines.
    Goroutine,
}

// --- Call Graph ---

/// Package identity for same-package taint symbol resolution.
///
/// Go packages are directories; the clause name distinguishes external test
/// packages (`package foo_test`) that share a directory with `package foo`.
/// Full import-path identity is deferred until deliberate import wiring exists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PackageIdentity {
    /// Parent directory of the unit path, `/`-normalized (`.` when the file
    /// has no directory component).
    pub dir: SharedText,
    /// `package` clause name from the source unit.
    pub name: SharedText,
}

impl PackageIdentity {
    /// Build package identity from a display path and source text.
    pub fn from_unit(path: &str, source: &str) -> Self {
        let normalized = path.replace('\\', "/");
        let dir = match normalized.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => parent,
            _ => ".",
        };
        let name = package_clause_name(source).unwrap_or("_");
        Self {
            dir: Arc::from(dir),
            name: Arc::from(name),
        }
    }
}

/// Project-level key for a function or method summary/declaration.
///
/// Keys combine package identity, optional receiver type, and bare name so
/// duplicate bare names in separate packages (or on different receivers)
/// cannot contaminate inter-procedural lookup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintSymbolKey {
    pub package: PackageIdentity,
    /// Normalized receiver type (`*Handler`, `Handler`); `None` for functions.
    pub receiver: Option<SharedText>,
    pub name: SharedText,
}

impl TaintSymbolKey {
    /// Key for a free function in `package`.
    pub fn function(package: PackageIdentity, name: impl Into<SharedText>) -> Self {
        Self {
            package,
            receiver: None,
            name: name.into(),
        }
    }

    /// Key for a method or function, using optional raw receiver text.
    pub fn with_receiver(
        package: PackageIdentity,
        receiver_raw: Option<&str>,
        name: impl Into<SharedText>,
    ) -> Self {
        Self {
            package,
            receiver: receiver_raw.map(normalize_receiver_type).map(Arc::from),
            name: name.into(),
        }
    }
}

/// Extract the `package` clause identifier from Go source (first match).
pub fn package_clause_name(source: &str) -> Option<&str> {
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("package ") {
            let name = rest
                .split(|c: char| c.is_whitespace() || c == '/')
                .next()
                .unwrap_or("")
                .trim();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// Normalize a method receiver parameter list / type fragment to a type key.
///
/// Accepts forms produced by the call-graph extractor such as `h *Handler`,
/// `*Handler`, or `(h Handler)`.
pub fn normalize_receiver_type(raw: &str) -> String {
    let s = raw
        .trim()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .trim();
    // parameter_declaration text: "name *Type" or "name Type" or just type.
    let tokens: Vec<&str> = s.split_whitespace().collect();
    match tokens.as_slice() {
        [] => String::new(),
        [only] => only.to_string(),
        [_, ty, ..] => ty.to_string(),
    }
}

/// A function declaration that can serve as a callee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionDecl {
    pub param_count: usize,
    pub is_method: bool,
    pub receiver_type: Option<SharedText>,
}

/// One call-expression in the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    pub caller: SharedText,
    pub callee: SharedText,
    pub byte_range: Range<usize>,
    pub arguments: Box<[SharedText]>,
    /// LHS of the assignment enclosing this call, when present.
    pub assignment_lhs: Option<SharedText>,
    /// Whether the call's result is returned by the enclosing function.
    pub returns_result: bool,
    pub is_method_call: bool,
    pub is_closure: bool,
}

/// Per-file call graph: flat sites + pre-built indexes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CallGraph {
    pub sites: Vec<CallSite>,
    pub by_caller: HashMap<SharedText, Vec<usize>>,
    pub by_callee: HashMap<SharedText, Vec<usize>>,
    pub declarations: HashMap<SharedText, FunctionDecl>,
}

impl CallGraph {
    /// Return call sites in source traversal order.
    pub fn sites(&self) -> &[CallSite] {
        &self.sites
    }

    /// Return indexes of sites grouped by caller.
    pub fn by_caller(&self) -> &HashMap<SharedText, Vec<usize>> {
        &self.by_caller
    }

    /// Return indexes of sites grouped by callee.
    pub fn by_callee(&self) -> &HashMap<SharedText, Vec<usize>> {
        &self.by_callee
    }

    /// Return discovered function declarations.
    pub fn declarations(&self) -> &HashMap<SharedText, FunctionDecl> {
        &self.declarations
    }

    pub(crate) fn add_declaration(&mut self, name: SharedText, declaration: FunctionDecl) {
        self.declarations.insert(name, declaration);
    }

    pub fn add_site(&mut self, site: CallSite) {
        let idx = self.sites.len();
        self.by_caller
            .entry(site.caller.clone())
            .or_default()
            .push(idx);
        self.by_callee
            .entry(site.callee.clone())
            .or_default()
            .push(idx);
        self.sites.push(site);
    }
}

/// Summary of a function's taint behavior for inter-procedural propagation.
#[derive(Debug, Clone, Default)]
pub struct TaintSummary {
    pub param_sources: Vec<Option<bool>>,
    pub return_sources: Vec<bool>,
    pub param_sanitizers: Vec<(usize, SanitizerKind)>,
    pub has_direct_sink: bool,
    pub sink_kinds: Vec<SinkKind>,
    /// Parameter indices that are `*T` pointers written to via `*p = source()`
    /// in the function body. Taint written through these params leaks back
    /// to the caller's variable (passed via `&x`).
    pub output_pointer_params: Vec<usize>,
}

/// Cross-file call graph, built by merging per-file CallGraphs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProjectCallGraph {
    pub calls: HashMap<String, Vec<CallSite>>,
    pub declarations: HashMap<String, FunctionDecl>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_identity_uses_parent_dir_and_clause() {
        let pkg = PackageIdentity::from_unit("pkg/good/handler.go", "package good\n");
        assert_eq!(pkg.dir.as_ref(), "pkg/good");
        assert_eq!(pkg.name.as_ref(), "good");
    }

    #[test]
    fn package_identity_root_file_uses_dot_dir() {
        let pkg = PackageIdentity::from_unit("main.go", "package main\n");
        assert_eq!(pkg.dir.as_ref(), ".");
        assert_eq!(pkg.name.as_ref(), "main");
    }

    #[test]
    fn package_identity_normalizes_backslashes() {
        let pkg = PackageIdentity::from_unit("pkg\\bad\\x.go", "package bad\n");
        assert_eq!(pkg.dir.as_ref(), "pkg/bad");
    }

    #[test]
    fn symbol_keys_differ_across_packages_with_same_bare_name() {
        let a = PackageIdentity::from_unit("a/x.go", "package a\n");
        let b = PackageIdentity::from_unit("b/x.go", "package b\n");
        let ka = TaintSymbolKey::function(a, Arc::from("openPath"));
        let kb = TaintSymbolKey::function(b, Arc::from("openPath"));
        assert_ne!(ka, kb);
    }

    #[test]
    fn symbol_keys_differ_by_receiver_type() {
        let pkg = PackageIdentity::from_unit("app/x.go", "package app\n");
        let k1 = TaintSymbolKey::with_receiver(pkg.clone(), Some("h *Handler"), Arc::from("Open"));
        let k2 = TaintSymbolKey::with_receiver(pkg, Some("s *Store"), Arc::from("Open"));
        assert_ne!(k1, k2);
        assert_eq!(k1.receiver.as_deref(), Some("*Handler"));
        assert_eq!(k2.receiver.as_deref(), Some("*Store"));
    }

    #[test]
    fn normalize_receiver_type_variants() {
        assert_eq!(normalize_receiver_type("h *Handler"), "*Handler");
        assert_eq!(normalize_receiver_type("*Handler"), "*Handler");
        assert_eq!(normalize_receiver_type("(h Handler)"), "Handler");
        assert_eq!(normalize_receiver_type("  "), "");
    }

    #[test]
    fn package_clause_skips_comments_and_takes_first() {
        let src = "// package fake\npackage real\n";
        assert_eq!(package_clause_name(src), Some("real"));
    }
}
