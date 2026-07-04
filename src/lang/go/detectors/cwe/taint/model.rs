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
}

// --- Call Graph ---

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
}

/// Cross-file call graph, built by merging per-file CallGraphs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProjectCallGraph {
    pub calls: HashMap<String, Vec<CallSite>>,
    pub declarations: HashMap<String, FunctionDecl>,
}
