/// Default severity for Go performance rules.
///
/// PERF rules are warnings by default: they do not block compilation or
/// deployment, they signal a likely hot-path improvement. Individual rule ids
/// can override this in [`fix_for`] / [`severity_for`] pairs.
pub const fn severity_for(_id: u32) -> crate::rules::Severity {
    crate::rules::Severity::Warning
}

pub const fn fix_for(id: u32) -> Option<&'static str> {
    match id {
        1 => Some("Compile the regular expression once at package scope and reuse the compiled pattern."),
        2 => Some("Hoist a strings.Builder (or preallocated bytes.Buffer) outside the loop and reuse it via Reset."),
        3 => Some("Hoist the slice out of the loop and reuse it via [:0] or a preallocated make with capacity."),
        4 => Some("Move the make call out of the loop and reuse the map via clear() or by passing it in."),
        5 => Some("Marshal or unmarshal once outside the loop, or stream with a reused encoder/decoder."),
        6 => Some("Use a bytes.Buffer, strings.Builder, or pool of buffers to avoid repeated fmt allocations."),
        7 => Some("Replace the defer with explicit close calls inside the loop or move the work into a helper function."),
        8 => Some("Hoist time.Parse out of the loop or cache parsed time values keyed by layout."),
        9 => Some("Parse each URL once outside the loop and store the *url.URL value."),
        10 => Some("Compile templates at process start with template.Must and reuse the parsed template."),
        11 => Some("Reuse a single http.Client (and Transport) declared at package scope."),
        12 => Some("Prepare the statement once at startup and reuse it, or use a connection-pooled helper."),
        13 => Some("Use a reusable *time.Timer with Stop+Reset, or a single time.Ticker, instead of time.After."),
        14 => Some("Hoist filepath.Glob / os.ReadDir out of the loop and cache the directory listing."),
        15 => Some("Use a strings.Builder or strconv.Append* to avoid repeated allocations."),
        16 => Some("Reuse a single bytes.Buffer by calling Reset at the start of each iteration."),
        17 => Some("Hoist a strings.Builder outside the loop or use strings.Join to avoid repeated concatenation."),
        18 => Some("Pass a reslice of the original slice instead of copying when the callee does not mutate."),
        19 => Some("Range by index (&slice[i]) or pointer to avoid copying each struct value."),
        20 => Some("Cache reflect.Type / reflect.Value at startup, or use code generation to avoid hot-path reflection."),
        21 => Some("Stream the request body via json.NewDecoder or io.Copy instead of fully buffering with io.ReadAll."),
        22 => Some("Load the file once at startup, or stream it, instead of reading on the request path."),
        23 => Some("Use a sync.Pool of *bytes.Reader or reuse a buffer across requests."),
        24 => Some("Hoist the hasher out of the loop and call h.Reset() each iteration instead of allocating a new hasher."),
        25 => Some("Generate the key pair once at startup and reuse the private key across requests."),
        _ => None,
    }
}
