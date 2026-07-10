use super::super::{SanitizerKind, SinkKind, SourceKind};

pub(super) fn classify_source(func_text: &str) -> Option<SourceKind> {
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
        // Gin/Echo framework: c.Query("name"), c.DefaultQuery("name","default")
        || call == "c.Query"
        || call == "c.DefaultQuery"
        || call == "c.QueryArray"
    {
        return Some(SourceKind::UserInput);
    }
    if call == "os.Args" || call == "flag.Args" || call == "flag.String" || call == "flag.Int" {
        return Some(SourceKind::Args);
    }
    if call == "os.Getenv" || call == "os.LookupEnv" {
        return Some(SourceKind::EnvVar);
    }
    if call == "io.ReadAll" || call.contains(".Scanner.Text") || call.contains(".Reader.ReadString")
    {
        return Some(SourceKind::File);
    }
    if call.contains(".Conn.Read") || call.contains("http.Request.Body") {
        return Some(SourceKind::Network);
    }
    None
}

pub(super) fn classify_sink(
    func_text: &str,
    call: tree_sitter::Node,
    src: &[u8],
) -> Option<(SinkKind, usize)> {
    let call_name = func_text;

    if call_name == "exec.Command" || call_name == "exec.CommandContext" {
        return Some((SinkKind::CommandExec, 0));
    }

    // stdlib database/sql + common ORM/query APIs (GORM Raw/Exec, sqlx).
    // First-arg taint is the SQL string; not full SQLi soundness.
    if call_name.ends_with(".Query")
        || call_name.ends_with(".Exec")
        || call_name.ends_with(".QueryRow")
        || call_name.ends_with(".QueryContext")
        || call_name.ends_with(".ExecContext")
        || call_name.ends_with(".QueryRowContext")
        || call_name.ends_with(".Raw") // GORM: db.Raw(userSQL)
        || call_name == "sqlx.Get"
        || call_name == "sqlx.Select"
        || call_name == "sqlx.NamedExec"
    {
        return Some((SinkKind::SQLQuery, 0));
    }

    if call_name == "os.Create"
        || call_name == "os.Open"
        || call_name == "os.OpenFile"
        || call_name == "os.ReadFile"
        || call_name == "os.WriteFile"
        || call_name == "ioutil.ReadFile"
        || call_name == "ioutil.WriteFile"
    {
        return Some((SinkKind::FileOpen, 0));
    }

    if call_name.ends_with(".Execute") || call_name.ends_with(".ExecuteTemplate") {
        return Some((SinkKind::Template, 1));
    }

    // HTTP response XSS sinks. Avoid bare `.Write` alone — that matches
    // csv.Writer.Write([]string) and other non-HTTP writers.
    if call_name == "fmt.Fprintf"
        || call_name.ends_with(".WriteString")
        || call_name.ends_with(".WriteHeader")
    {
        return Some((SinkKind::HTTPWrite, 0));
    }
    if call_name.ends_with(".Write") && http_write_looks_like_response_writer(call, src) {
        return Some((SinkKind::HTTPWrite, 0));
    }

    // XML-specific sinks (before generic .Decode in Deserialization below).
    if call_name == "xml.Unmarshal" || call_name.ends_with(".DecodeElement") {
        return Some((SinkKind::XMLQuery, 0));
    }

    if call_name == "json.Unmarshal"
        || call_name.ends_with(".Decode")
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

    if call_name == "ldap.Dial"
        || call_name == "ldap.Search"
        || call_name == "ldap.SearchByAttribute"
        || call_name == "ldap.NewSearchRequest"
    {
        return Some((SinkKind::LDAPQuery, 0));
    }

    // Check whether the first argument is a `template.HTML` cast.
    if is_template_html_call(call, src) {
        return Some((SinkKind::Template, 0));
    }

    None
}

pub(crate) fn classify_sanitizer(func_text: &str) -> Option<SanitizerKind> {
    let call = func_text;
    // filepath.Clean / path.Clean alone are NOT path-traversal safe — they do not
    // confine the path under a root. Only Base (strips to final component) and
    // confinement helpers count as Path sanitizers; confinement is also checked
    // separately via Abs/EvalSymlinks + HasPrefix on the taint path.
    if call == "filepath.Base" {
        return Some(SanitizerKind::Path);
    }
    if call == "html.EscapeString"
        || call.contains("template.HTMLEscaper")
        || call.contains("template.JSEscaper")
        || call == "html.UnescapeString"
    {
        return Some(SanitizerKind::HTML);
    }
    if call == "url.QueryEscape" || call == "url.PathEscape" {
        return Some(SanitizerKind::URL);
    }
    if call.starts_with("regexp.") && call.contains(".MatchString") {
        return Some(SanitizerKind::Validation);
    }
    if call == "strconv.Atoi"
        || call == "strconv.ParseInt"
        || call == "strconv.ParseFloat"
        || call == "strconv.ParseUint"
    {
        return Some(SanitizerKind::Validation);
    }
    if call == "len" {
        return Some(SanitizerKind::Bounded);
    }
    if call == "ldap.EscapeFilter" {
        return Some(SanitizerKind::LDAP);
    }
    if call == "xml.EscapeText" || call == "xml.Marshal" {
        return Some(SanitizerKind::XML);
    }
    // Do NOT treat bare `.Prepare` as a sanitizer: Prepare with a dynamic SQL
    // string is still injectable. Safe pattern is a *literal* first arg at the
    // Query/Exec sink (see is_parameterized_query in cwe_89). Same-variable
    // Prepare→Stmt.Query proof is not implemented yet.

    // Name-based heuristic: only well-known sanitizer prefixes. Intentionally
    // does NOT match bare "clean" (filepath.Clean is not path-safe by itself).
    // Imprecise — may still match unrelated functions; prefer known-safe APIs.
    if let Some(name) = call.rsplit('.').next().or(Some(call)) {
        let lower = name.to_lowercase();
        if lower.starts_with("sanitize")
            || lower.starts_with("escape")
            || lower.starts_with("validate")
            || lower.starts_with("purify")
        {
            return Some(SanitizerKind::Validation);
        }
    }
    None
}

pub(super) fn receiver_of_method_call<'a>(
    call: tree_sitter::Node,
    src: &'a [u8],
) -> Option<&'a str> {
    let func = call.child_by_field_name("function")?;
    if func.kind() != "selector_expression" {
        return None;
    }
    let operand = func.child_by_field_name("operand")?;
    operand.utf8_text(src).ok()
}

pub(super) fn is_template_html_call(call: tree_sitter::Node, src: &[u8]) -> bool {
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

/// Heuristic: only treat `.Write` as an HTTP XSS sink for common
/// `http.ResponseWriter` receivers. Avoid hmac.Write, csv.Writer, bufio, etc.
fn http_write_looks_like_response_writer(call: tree_sitter::Node, src: &[u8]) -> bool {
    if let Some(args) = call.child_by_field_name("arguments") {
        let mut cursor = args.walk();
        if let Some(first) = args.named_children(&mut cursor).next() {
            if let Ok(text) = first.utf8_text(src) {
                let t = text.trim();
                // csv.Writer.Write([]string{...}) — not XSS.
                if t.starts_with("[]string") {
                    return false;
                }
            }
        }
    }
    match receiver_of_method_call(call, src) {
        Some("w") | Some("rw") | Some("resp") => true,
        Some(recv) if recv.contains("ResponseWriter") => true,
        // Do not treat unknown receivers (hmac, hash, csv, bufio, …) as HTTPWrite.
        _ => false,
    }
}

pub(super) fn is_source_or_sanitizer_call(rhs: &str) -> bool {
    if let Some(call) = rhs.split('(').next() {
        let trimmed = call.trim();
        if classify_source(trimmed).is_some() {
            return true;
        }
        if classify_sanitizer(trimmed).is_some() {
            return true;
        }
        // Also suppress identifier wiring for known sink calls — a sink's
        // return value should not be tainted by its arguments.
        if is_sink_call_by_name(trimmed) {
            return true;
        }
    }
    // Also check if the RHS contains any sanitizer call nested inside
    // (e.g. `filepath.Join(baseDir, filepath.Clean(name))`).
    for (name, _) in KNOWN_SANITIZER_CALLS {
        if rhs.contains(name) {
            return true;
        }
    }
    false
}

/// Function-name-only subset of `classify_sink` — doesn't need tree-sitter node.
fn is_sink_call_by_name(func_text: &str) -> bool {
    let n = func_text;
    n == "exec.Command"
        || n == "exec.CommandContext"
        || n.ends_with(".Query")
        || n.ends_with(".Exec")
        || n.ends_with(".QueryRow")
        || n == "os.Create"
        || n == "os.Open"
        || n == "os.OpenFile"
        || n == "os.ReadFile"
        || n == "os.WriteFile"
        || n == "ioutil.ReadFile"
        || n == "ioutil.WriteFile"
        || n.ends_with(".Write")
        || n.ends_with(".Execute")
        || n.ends_with(".ExecuteTemplate")
        || n == "fmt.Fprintf"
        || n == "xml.Unmarshal"
        || n.ends_with(".DecodeElement")
        || n == "json.Unmarshal"
        || n.ends_with(".Decode")
        || n.contains("gob.NewDecoder")
        || n == "ldap.Dial"
        || n == "ldap.Search"
        || n == "ldap.SearchByAttribute"
        || n == "ldap.NewSearchRequest"
}

// ponytail: static list avoids re-parsing; add new sanitizers here when
// adding them to classify_sanitizer.
const KNOWN_SANITIZER_CALLS: &[(&str, &str)] = &[
    // filepath.Clean / path.Clean intentionally omitted — not path-safe alone.
    ("filepath.Base(", "path"),
    ("html.EscapeString(", "html"),
    ("html.UnescapeString(", "html"),
    ("ldap.EscapeFilter(", "ldap"),
    ("xml.EscapeText(", "xml"),
    ("xml.Marshal(", "xml"),
];
