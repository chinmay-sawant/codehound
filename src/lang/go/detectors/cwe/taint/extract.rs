//! Single-pass tree-sitter extraction of taint-relevant facts.

use std::ops::Range;
use std::sync::Arc;

use crate::core::ParsedUnit;

use super::{
    AssignmentDetail, SanitizerKind, ScopeId, ScopeInfo, ScopeKind, SharedText, SinkKind,
    SourceKind, TaintAnnotations, TaintSanitizerAnnotation, TaintSinkAnnotation,
    TaintSourceAnnotation,
};

/// Extract taint annotations from a parsed Go source unit.
pub fn extract_taint_facts(unit: &ParsedUnit) -> TaintAnnotations {
    let src = unit.source.as_bytes();
    let root = unit.tree.root_node();
    let mut state = ExtractionState::new(unit.source.as_ref());

    let mut cursor = root.walk();
    walk_node(root, &mut cursor, src, &mut state);

    TaintAnnotations {
        sources: state.sources,
        sinks: state.sinks,
        sanitizers: state.sanitizers,
        assignments: state.assignments,
        scopes: state.scopes,
    }
}

struct ExtractionState<'a> {
    src_bytes: &'a [u8],
    scopes: Vec<ScopeInfo>,
    scope_stack: Vec<ScopeId>,
    next_scope_id: ScopeId,
    current_function: Option<SharedText>,
    sources: Vec<TaintSourceAnnotation>,
    sinks: Vec<TaintSinkAnnotation>,
    sanitizers: Vec<TaintSanitizerAnnotation>,
    assignments: Vec<AssignmentDetail>,
}

impl<'a> ExtractionState<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            src_bytes: source.as_bytes(),
            scopes: Vec::new(),
            scope_stack: Vec::new(),
            next_scope_id: 0,
            current_function: None,
            sources: Vec::new(),
            sinks: Vec::new(),
            sanitizers: Vec::new(),
            assignments: Vec::new(),
        }
    }

    fn push_scope(&mut self, kind: ScopeKind, byte_range: Range<usize>) -> ScopeId {
        let id = self.next_scope_id;
        self.next_scope_id += 1;
        let parent = self.scope_stack.last().copied();
        self.scopes.push(ScopeInfo {
            id,
            parent,
            kind,
            byte_range,
            function: self.current_function.clone(),
        });
        self.scope_stack.push(id);
        id
    }

    fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    fn current_scope(&self) -> ScopeId {
        self.scope_stack
            .last()
            .copied()
            .expect("scope stack must never be empty at root")
    }
}

fn walk_node(
    node: tree_sitter::Node,
    cursor: &mut tree_sitter::TreeCursor,
    src: &[u8],
    state: &mut ExtractionState<'_>,
) {
    let mut entered_scope = None;

    match node.kind() {
        "function_declaration" | "func_literal" | "method_declaration" => {
            let func_name = node
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
                .unwrap_or("<anonymous>");
            let func_name: SharedText = Arc::from(func_name);
            state.current_function = Some(func_name.clone());
            entered_scope = Some((
                ScopeKind::Function,
                node.start_byte()..node.end_byte(),
                Some(func_name),
            ));
        }
        "block" => {
            entered_scope = Some((
                ScopeKind::Block,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "if_statement" => {
            entered_scope = Some((
                ScopeKind::If,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "for_statement" | "range_clause" => {
            entered_scope = Some((
                ScopeKind::For,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "switch_statement" | "expression_switch_statement" => {
            entered_scope = Some((
                ScopeKind::Switch,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "case_clause" | "default_case" => {
            entered_scope = Some((
                ScopeKind::Case,
                node.start_byte()..node.end_byte(),
                state.current_function.clone(),
            ));
        }
        "call_expression" => {
            record_call(node, state);
        }
        "assignment_statement" | "short_var_declaration" => {
            record_assignment(node, state);
        }
        _ => {}
    }

    if let Some((kind, ref range, _)) = entered_scope {
        state.push_scope(kind, range.clone());
    }

    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            walk_node(child, cursor, src, state);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }

    if entered_scope.is_some() {
        state.pop_scope();
        if matches!(entered_scope, Some((ScopeKind::Function, _, _))) {
            state.current_function = None;
        }
    }
}

fn record_call(node: tree_sitter::Node, state: &mut ExtractionState<'_>) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let Some(func_text) = func.utf8_text(state.src_bytes).ok() else {
        return;
    };

    // Skip wrapper calls where the receiver is itself a call, e.g.
    // `r.URL.Query().Get("x")` — we classify the inner `r.URL.Query()` source.
    if is_chained_call(func) {
        return;
    }

    let byte_range = node.start_byte()..node.end_byte();

    if let Some(kind) = classify_source(func_text) {
        let args = argument_texts(node, state.src_bytes)
            .into_iter()
            .map(Arc::from)
            .collect::<Vec<_>>();
        let result_var = result_variable_of_call(node, state.src_bytes);
        state.sources.push(TaintSourceAnnotation {
            function: Arc::from(func_text),
            kind,
            byte_range,
            result_variable: result_var.map(|s| Arc::from(s)),
            arguments: args.into_boxed_slice(),
        });
        return;
    }

    if let Some((kind, arg_index)) = classify_sink(func_text, node, state.src_bytes) {
        let args = argument_texts(node, state.src_bytes)
            .into_iter()
            .map(Arc::from)
            .collect::<Vec<_>>();
        let arg_text = args.get(arg_index).cloned().unwrap_or_default();
        state.sinks.push(TaintSinkAnnotation {
            function: Arc::from(func_text),
            kind,
            argument_index: arg_index,
            argument_text: arg_text,
            all_arguments: args.into_boxed_slice(),
            byte_range,
        });
        return;
    }

    if let Some(kind) = classify_sanitizer(func_text) {
        let args = argument_texts(node, state.src_bytes)
            .into_iter()
            .map(Arc::from)
            .collect::<Vec<_>>();
        let result_var = result_variable_of_call(node, state.src_bytes);
        state.sanitizers.push(TaintSanitizerAnnotation {
            function: Arc::from(func_text),
            kind,
            byte_range,
            result_variable: result_var.map(|s| Arc::from(s)),
            arguments: args.into_boxed_slice(),
        });
    }
}

fn is_chained_call(func_node: tree_sitter::Node) -> bool {
    if func_node.kind() != "selector_expression" {
        return false;
    }
    let Some(operand) = func_node.child_by_field_name("operand") else {
        return false;
    };
    operand.kind() == "call_expression"
}

fn record_assignment(node: tree_sitter::Node, state: &mut ExtractionState<'_>) {
    let Some(text) = node.utf8_text(state.src_bytes).ok() else {
        return;
    };
    let Some((lhs, rhs)) = split_assignment(text) else {
        return;
    };
    let names = extract_identifiers(lhs);
    if names.is_empty() {
        return;
    }
    let scope = state.current_scope();
    let byte_range = node.start_byte()..node.end_byte();
    let from_call = is_source_or_sanitizer_call(rhs);
    for name in names {
        state.assignments.push(AssignmentDetail {
            lhs: Arc::from(name),
            rhs_text: Arc::from(rhs),
            scope,
            byte_range: byte_range.clone(),
            from_source_or_sanitizer: from_call,
        });
    }
}

fn result_variable_of_call<'a>(call: tree_sitter::Node, src: &'a [u8]) -> Option<&'a str> {
    // Tree-sitter Go: a short_var_declaration or assignment_statement whose
    // right child is the call_expression. We climb to the parent statement.
    let mut parent = call.parent()?;
    while !matches!(
        parent.kind(),
        "assignment_statement" | "short_var_declaration"
    ) {
        parent = parent.parent()?;
    }
    let left = parent.child_by_field_name("left")?;
    left.utf8_text(src).ok().map(str::trim)
}

pub(crate) fn argument_texts<'a>(call: tree_sitter::Node, src: &'a [u8]) -> Vec<&'a str> {
    let Some(args) = call.child_by_field_name("arguments") else {
        return Vec::new();
    };
    let mut cursor = args.walk();
    args.named_children(&mut cursor)
        .filter_map(|n| n.utf8_text(src).ok().map(str::trim))
        .collect()
}

fn classify_source(func_text: &str) -> Option<SourceKind> {
    let call = func_text;
    if call.contains(".URL.Query")
        || call.contains(".FormValue")
        || call.contains(".PostForm")
        || call.contains(".Header.Get")
        || call.contains(".GetHeader")
        || call.contains(".GetRawData")
        || call == "io.ReadAll(r.Body)"
        || call.contains(".PathValue")
        || call.contains(".Param")
    {
        return Some(SourceKind::UserInput);
    }
    if call == "os.Args" || call == "flag.Args" || call == "flag.String" || call == "flag.Int" {
        return Some(SourceKind::Args);
    }
    if call == "os.Getenv" || call == "os.LookupEnv" {
        return Some(SourceKind::EnvVar);
    }
    if call == "os.ReadFile"
        || call == "ioutil.ReadFile"
        || call == "io.ReadAll"
        || call.contains(".Scanner.Text")
        || call.contains(".Reader.ReadString")
    {
        return Some(SourceKind::File);
    }
    if call.contains(".Conn.Read") || call.contains("http.Request.Body") {
        return Some(SourceKind::Network);
    }
    None
}

fn classify_sink(
    func_text: &str,
    call: tree_sitter::Node,
    src: &[u8],
) -> Option<(SinkKind, usize)> {
    let call_name = func_text;

    if call_name == "exec.Command" || call_name == "exec.CommandContext" {
        return Some((SinkKind::CommandExec, 0));
    }

    if call_name.ends_with(".Query")
        || call_name.ends_with(".Exec")
        || call_name.ends_with(".QueryRow")
    {
        return Some((SinkKind::SQLQuery, 0));
    }

    if call_name == "os.Create"
        || call_name == "os.Open"
        || call_name == "os.OpenFile"
        || call_name == "os.WriteFile"
        || call_name == "ioutil.WriteFile"
    {
        return Some((SinkKind::FileOpen, 0));
    }

    if call_name.ends_with(".Execute") || call_name.ends_with(".ExecuteTemplate") {
        return Some((SinkKind::Template, 1));
    }

    if call_name.ends_with(".Write") || call_name == "fmt.Fprintf" {
        return Some((SinkKind::HTTPWrite, 0));
    }

    if call_name == "json.Unmarshal"
        || call_name.ends_with(".Decode")
        || call_name == "xml.Unmarshal"
        || call_name.contains("gob.NewDecoder")
    {
        return Some((SinkKind::Deserialization, 0));
    }

    // Method-call form detection for command methods.
    if call_name.ends_with(".Run")
        || call_name.ends_with(".Start")
        || call_name.ends_with(".Output")
    {
        if let Some(receiver) = receiver_of_method_call(call, src) {
            if receiver.contains("exec.Command") || receiver.starts_with("exec.") {
                return Some((SinkKind::CommandExec, 0));
            }
        }
    }

    // Check whether the first argument is a `template.HTML` cast.
    if is_template_html_call(call, src) {
        return Some((SinkKind::Template, 0));
    }

    None
}

fn classify_sanitizer(func_text: &str) -> Option<SanitizerKind> {
    let call = func_text;
    if call == "filepath.Clean" || call == "path.Clean" {
        return Some(SanitizerKind::Path);
    }
    if call == "html.EscapeString"
        || call.contains("template.HTMLEscaper")
        || call.contains("template.JSEscaper")
    {
        return Some(SanitizerKind::HTML);
    }
    if call == "url.QueryEscape" || call == "url.PathEscape" {
        return Some(SanitizerKind::URL);
    }
    if call.starts_with("regexp.") && call.contains(".MatchString") {
        return Some(SanitizerKind::Validation);
    }
    if call == "len" {
        return Some(SanitizerKind::Bounded);
    }
    // Prepared statements are handled by the SQL sanitizer path.
    if call.ends_with(".Prepare") {
        return Some(SanitizerKind::SQL);
    }
    None
}

fn receiver_of_method_call<'a>(call: tree_sitter::Node, src: &'a [u8]) -> Option<&'a str> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "selector_expression" {
        return None;
    }
    let operand = func.child_by_field_name("operand")?;
    operand.utf8_text(src).ok()
}

fn is_template_html_call(call: tree_sitter::Node, src: &[u8]) -> bool {
    let Some(args) = call.child_by_field_name("arguments") else {
        return false;
    };
    let mut cursor = args.walk();
    let first = args
        .named_children(&mut cursor)
        .next()
        .and_then(|n| n.utf8_text(src).ok());
    matches!(first, Some(t) if t.starts_with("template.HTML("))
}

fn split_assignment(text: &str) -> Option<(&str, &str)> {
    if let Some((lhs, rhs)) = text.split_once(":=") {
        return Some((lhs.trim(), rhs.trim()));
    }
    let (lhs, rhs) = text.split_once('=')?;
    Some((lhs.trim(), rhs.trim()))
}

fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}

fn is_source_or_sanitizer_call(rhs: &str) -> bool {
    if let Some(call) = rhs.split('(').next() {
        let trimmed = call.trim();
        if classify_source(trimmed).is_some() {
            return true;
        }
        if classify_sanitizer(trimmed).is_some() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::super::{ScopeKind, SinkKind, SourceKind};
    use super::*;

    fn parse(source: &str) -> ParsedUnit {
        crate::lang::go::parser::parse_go(source).expect("valid Go")
    }

    #[test]
    fn extracts_user_input_source() {
        let source = r#"package main
func handler(w http.ResponseWriter, r *http.Request) {
    q := r.URL.Query().Get("x")
    _ = q
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        assert_eq!(facts.sources.len(), 1);
        assert_eq!(facts.sources[0].kind, SourceKind::UserInput);
        assert!(facts.sources[0].function.as_ref().contains("Query"));
    }

    #[test]
    fn extracts_command_sink() {
        let source = r#"package main
func run(name string) {
    exec.Command("sh", "-c", name)
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        assert_eq!(facts.sinks.len(), 1);
        assert_eq!(facts.sinks[0].kind, SinkKind::CommandExec);
    }

    #[test]
    fn extracts_scopes() {
        let source = r#"package main
func f() {
    if true {
        x := 1
        _ = x
    }
}"#;
        let unit = parse(source);
        let facts = extract_taint_facts(&unit);
        assert!(facts.scopes.iter().any(|s| s.kind == ScopeKind::Function));
        assert!(facts.scopes.iter().any(|s| s.kind == ScopeKind::If));
    }

    #[test]
    fn taint_extraction_overhead_is_small() {
        use std::time::Instant;

        let mut lines = String::from("package main\n");
        for i in 0..500 {
            lines.push_str(&format!(
                "func f{i}(w http.ResponseWriter, r *http.Request) {{
    q := r.URL.Query().Get(\"x\")
    cmd := exec.Command(\"sh\", \"-c\", q)
    _ = cmd
}}\n"
            ));
        }
        let unit = parse(&lines);

        let start = Instant::now();
        let facts = extract_taint_facts(&unit);
        let elapsed = start.elapsed();

        assert_eq!(facts.sources.len(), 500);
        assert_eq!(facts.sinks.len(), 500);
        assert!(
            elapsed.as_millis() < 50,
            "taint extraction on 500-function file took {elapsed:?}, budget 50ms"
        );
    }
}
