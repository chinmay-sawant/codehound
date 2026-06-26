//! Taint-analysis data model: kinds, nodes, edges, scopes, annotations.

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
