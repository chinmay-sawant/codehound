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

pub(super) fn classify_sink(
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

pub(super) fn classify_sanitizer(func_text: &str) -> Option<SanitizerKind> {
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

pub(super) fn is_source_or_sanitizer_call(rhs: &str) -> bool {
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
