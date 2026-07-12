//! PERF-225–231: large-buffer ownership, compress writers, string→append chains,
//! loop-invariant pure calls, and PEM/key parse on hot paths.

use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::common::{
    char_boundary, is_hot_path, is_in_loop, is_request_path,
};
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::*;
use crate::rules::{Finding, emit};

/// PERF-225: Redundant Large Slice Clone
pub(crate) fn detect_perf_225(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    use crate::lang::go::detectors::perf::common::enclosing_function_name;

    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let mut sites: Vec<(usize, String)> = Vec::new();
    for call in &facts.calls {
        if call.callee.as_ref() != "slices.Clone" {
            continue;
        }
        let arg = call
            .arguments
            .first()
            .map(|a| a.trim().to_string())
            .unwrap_or_default();
        sites.push((call.start_byte, arg));
    }
    for site in append_nil_clones(source) {
        sites.push(site);
    }
    if sites.len() < 2 {
        return;
    }

    // Same identifier cloned twice.
    for i in 0..sites.len() {
        for j in (i + 1)..sites.len() {
            if !sites[i].1.is_empty() && sites[i].1 == sites[j].1 {
                let (line, col) = unit.line_col(sites[j].0);
                emit::push_finding(
                    &META_PERF_225,
                    file,
                    line,
                    col,
                    "large slice is fully cloned more than once; keep a single owned buffer",
                    out,
                );
                return;
            }
        }
    }

    // Clone chain in one function (unsigned then signed full copies).
    sites.sort_by_key(|(b, _)| *b);
    let (first, second) = (sites[0].0, sites[1].0);
    if enclosing_function_name(source, first) == enclosing_function_name(source, second)
        && enclosing_function_name(source, first).is_some()
    {
        let (line, col) = unit.line_col(second);
        emit::push_finding(
            &META_PERF_225,
            file,
            line,
            col,
            "large slice is fully cloned more than once; keep a single owned buffer",
            out,
        );
    }
}

/// PERF-226: Post-Producer Buffer Re-Copy
///
/// Covers the classic pprof pattern:
///   `cp := make([]byte, buf.Len()); copy(cp, buf.Bytes())`
/// after compress Close / buffer production, and Clone after Bytes().
pub(crate) fn detect_perf_226(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let mut emitted = 0u32;

    // 1) Explicit make(len/Len) + copy(...Bytes()) — does not rely on Close proximity.
    let mut search = 0usize;
    while let Some(rel) = source[search..].find("make([]byte") {
        let start = search + rel;
        let window_end = char_boundary(source, (start + 200).min(source.len()));
        let window = &source[start..window_end];
        // make([]byte, x.Len()) or make([]byte, len(x)) then copy(..., x.Bytes()) / copy(..., x)
        let make_len = window.contains(".Len()") || window.contains("len(");
        let has_copy = window.contains("copy(");
        let from_bytes = window.contains(".Bytes()") || window.contains("copy(");
        if make_len && has_copy && from_bytes {
            let (line, col) = unit.line_col(start);
            emit::push_finding(
                &META_PERF_226,
                file,
                line,
                col,
                "buffer is re-copied after production (make+copy); take ownership of the producer buffer",
                out,
            );
            emitted += 1;
            if emitted >= 8 {
                return;
            }
        }
        search = start + 4;
    }

    // 2) Producer markers: .Bytes() / .Close() then Clone or make+copy in a wide window.
    let producer_needles = [".Bytes()", ".Close()"];
    for needle in producer_needles {
        let mut search = 0usize;
        while let Some(rel) = source[search..].find(needle) {
            let prod = search + rel;
            // Wide enough for error-handling blocks between Close and make+copy.
            let window_end = char_boundary(source, (prod + 480).min(source.len()));
            let window = &source[prod..window_end];
            if window_has_recopy(window) {
                let recopy_rel = window
                    .find("make([]byte")
                    .or_else(|| window.find("slices.Clone("))
                    .unwrap_or(0);
                let abs = prod + recopy_rel;
                // Avoid double-reporting the same make site from step 1.
                let already = out
                    .iter()
                    .any(|f| f.rule_id == "PERF-226" && f.line == unit.line_col(abs).0);
                if !already {
                    let (line, col) = unit.line_col(abs);
                    emit::push_finding(
                        &META_PERF_226,
                        file,
                        line,
                        col,
                        "buffer is re-copied immediately after production; take ownership instead of make+copy",
                        out,
                    );
                    emitted += 1;
                    if emitted >= 8 {
                        return;
                    }
                }
            }
            search = prod + needle.len();
        }
    }
    let _ = facts;
}

/// PERF-228: Parallel Fan-Out For Tiny Workset (N ≤ 2).
///
/// Spawning errgroup/WaitGroup/go over a 1–2 element composite often costs more
/// than doing the work serially.
pub(crate) fn detect_perf_228(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Named slices assigned from small composite literals in this unit.
    let tiny_names = tiny_composite_slice_names(source);
    // Also accept inline `range []T{...}` with ≤2 elems (handled per-loop).

    for &(loop_start, loop_end) in &facts.for_ranges {
        let end = loop_end.min(source.len()).max(loop_start);
        let loop_text = &source[loop_start..end];
        if !loop_has_parallel_fanout(loop_text) {
            continue;
        }
        // Inline composite: `for _, x := range []T{a}` / `[]T{a, b}`
        if let Some(n) = composite_elem_count_after_range(loop_text) {
            if (1..=2).contains(&n) {
                let (line, col) = unit.line_col(loop_start);
                emit::push_finding(
                    &META_PERF_228,
                    file,
                    line,
                    col,
                    "parallel fan-out over a 1–2 element workset; prefer a serial path for tiny N",
                    out,
                );
                return;
            }
        }
        // Named target from a tiny composite in the same function/file.
        if let Some(target) = range_target_name(loop_text) {
            if tiny_names.iter().any(|n| n == target) {
                let (line, col) = unit.line_col(loop_start);
                emit::push_finding(
                    &META_PERF_228,
                    file,
                    line,
                    col,
                    "parallel fan-out over a 1–2 element workset; prefer a serial path for tiny N",
                    out,
                );
                return;
            }
        }
    }
}

/// PERF-227: Compress Writer Allocated Without Pool
///
/// File-level pool helpers (GetZlibWriter) must not silence NewWriter* in
/// *other* functions — only suppress when the enclosing function itself
/// implements pool Get/Reset or is named like a pool factory.
pub(crate) fn detect_perf_227(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    use crate::lang::go::detectors::perf::common::enclosing_function_name;

    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let triggers = [
        "flate.NewWriter",
        "flate.NewWriterDict",
        "zlib.NewWriter",
        "zlib.NewWriterLevel",
        "gzip.NewWriter",
        "gzip.NewWriterLevel",
    ];

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !triggers.contains(&callee) {
            continue;
        }
        let fname = enclosing_function_name(source, call.start_byte).unwrap_or("");
        let fname_l = fname.to_ascii_lowercase();
        // Pool factory / getter — constructing the writer once for Pool.New is fine.
        if fname_l.contains("getzlib")
            || fname_l.contains("getflate")
            || fname_l.contains("getgzip")
            || fname_l.contains("newpool")
            || (fname_l.starts_with("get") && fname_l.contains("writer"))
        {
            continue;
        }
        // Enclosing body uses Reset on the writer (proper reuse path).
        if function_body_has_writer_reset(source, call.start_byte) {
            continue;
        }
        if !is_hot_path(
            source,
            call.start_byte,
            &facts.source_index,
            is_in_loop(call),
        ) {
            // Still flag compress construction inside any non-tiny helper that
            // is not a one-shot main/init — encode paths often lack HTTP shape.
            if fname.is_empty() || fname == "init" || fname == "main" {
                continue;
            }
            // Require compress-shaped name for non-hot encode helpers.
            if !compress_shaped_fname(&fname_l) {
                continue;
            }
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_227,
            file,
            line,
            col,
            "compress writer is allocated without local pool/Reset reuse; pool writers on hot paths",
            out,
        );
        // Report multiple sites (main path + side paths), not only the first.
    }
}

/// PERF-233: Default / BestCompression flate level on a hot encode path.
///
/// Distinct from PERF-227 (pool/Reset): this flags compression *level* choice.
/// Hot stream encoders can use BestSpeed (or level 1) when size budgets allow —
/// static smell when DefaultCompression, BestCompression, or default NewWriter
/// level is used on hot paths.
pub(crate) fn detect_perf_233(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    use crate::lang::go::detectors::perf::common::enclosing_function_name;

    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    let mut emitted = 0u32;

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        let args_joined = call
            .arguments
            .iter()
            .map(|a| a.as_ref())
            .collect::<Vec<_>>()
            .join(",");
        // Explicit fast levels are fine (also silences pool factories using BestSpeed).
        if args_joined.contains("BestSpeed")
            || args_joined.contains("HuffmanOnly")
            || args_joined.contains("NoCompression")
        {
            continue;
        }
        let uses_slow = match callee {
            // zlib.NewWriter / gzip.NewWriter always use DefaultCompression.
            "zlib.NewWriter" | "gzip.NewWriter" => true,
            // Level APIs: only explicit slow constants (not free-form level vars).
            "zlib.NewWriterLevel"
            | "flate.NewWriter"
            | "flate.NewWriterLevel"
            | "gzip.NewWriterLevel" => {
                args_joined.contains("DefaultCompression")
                    || args_joined.contains("BestCompression")
            }
            _ => false,
        };
        if !uses_slow {
            continue;
        }
        // Only care on hot / compress-shaped functions (align tokens with 227).
        if !is_hot_path(
            source,
            call.start_byte,
            &facts.source_index,
            is_in_loop(call),
        ) {
            let fname = enclosing_function_name(source, call.start_byte)
                .unwrap_or("")
                .to_ascii_lowercase();
            if fname.is_empty() || fname == "init" || fname == "main" {
                continue;
            }
            if !compress_shaped_fname(&fname) {
                continue;
            }
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_233,
            file,
            line,
            col,
            "compress uses Default/BestCompression on a hot path; consider BestSpeed (or level 1) when size budget allows",
            out,
        );
        emitted += 1;
        if emitted >= 8 {
            return;
        }
    }
}

/// Function-name tokens that look like bulk compress / encode paths.
/// Shared by PERF-227 (pool) and PERF-233 (level) non-hot gates.
/// Portable verbs only — no product- or document-format tokens.
fn compress_shaped_fname(fname_l: &str) -> bool {
    fname_l.contains("compress")
        || fname_l.contains("encode")
        || fname_l.contains("write")
        || fname_l.contains("generate")
        || fname_l.contains("render")
        || fname_l.contains("export")
        || fname_l.contains("build")
        || fname_l.contains("stream")
        || fname_l.contains("serialize")
        || fname_l.contains("marshal")
}

fn function_body_has_writer_reset(source: &str, start_byte: usize) -> bool {
    let head = &source[..start_byte.min(source.len())];
    let Some(func_kw) = head.rfind("func ") else {
        return false;
    };
    let Some(brace_rel) = source[func_kw..].find('{') else {
        return false;
    };
    let body_open = func_kw + brace_rel;
    let mut depth = 0i32;
    let mut end = body_open;
    for (i, ch) in source[body_open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end = body_open + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let body = &source[body_open..end.min(source.len())];
    body.contains(".Reset(") || body.contains("Reset(")
}

/// PERF-229: Intermediate String On Byte Append Path
pub(crate) fn detect_perf_229(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Find assignments from Itoa / FormatInt / Sprintf
    for assignment in &facts.assignments {
        let expr = assignment.expr.as_ref();
        let is_fmt = expr.contains("strconv.Itoa(")
            || expr.contains("strconv.FormatInt(")
            || expr.contains("strconv.FormatUint(")
            || expr.contains("fmt.Sprintf(");
        if !is_fmt {
            continue;
        }
        let name = assignment
            .text
            .as_ref()
            .split('=')
            .next()
            .unwrap_or("")
            .trim();
        // text may be "s :=" form stored differently — use lhs from assignment
        let name = if name.is_empty() || name.contains('(') {
            // fall back: look at common pattern in source near assignment
            continue_name_from_source(source, assignment.start_byte).unwrap_or("")
        } else {
            name.trim_end_matches(':').trim()
        };
        if !is_simple_ident(name) {
            continue;
        }
        let after = &source[assignment.start_byte..];
        let window = &after[..after.len().min(200)];
        if window.contains("append(") && window.contains(name)
            || window.contains(&format!("WriteString({name})"))
            || window.contains(&format!("[]byte({name})"))
        {
            // Tighten: append(..., name...) or WriteString(name)
            if window.contains(&format!("{name}..."))
                || window.contains(&format!("WriteString({name})"))
                || window.contains(&format!("[]byte({name})"))
            {
                let (line, col) = unit.line_col(assignment.start_byte);
                emit::push_finding(
                    &META_PERF_229,
                    file,
                    line,
                    col,
                    "temporary string is built then appended to bytes; use AppendInt/append-style APIs",
                    out,
                );
                return;
            }
        }
    }

    // Text-level fallback for fixture simplicity
    if let Some(byte) = source.find("strconv.Itoa(") {
        let window_end = char_boundary(source, (byte + 160).min(source.len()));
        let window = &source[byte..window_end];
        if window.contains("append(") && window.contains("...") {
            let (line, col) = unit.line_col(byte);
            emit::push_finding(
                &META_PERF_229,
                file,
                line,
                col,
                "temporary string is built then appended to bytes; use AppendInt/append-style APIs",
                out,
            );
        }
    }
}

/// PERF-230: Pure Function Re-Evaluated In Loop With Stable Args
///
/// Targets loop-invariant parse / measure / resolve / width helpers re-called
/// with stable args every iteration.
///
/// Intentionally does **not** fire on stdlib `time.Parse` / `strconv.Parse*` /
/// pool `Get` / crypto `x509.Parse*` (PEM/key parse is PERF-231).
pub(crate) fn detect_perf_230(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let mut emitted = 0u32;

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        let callee = call.callee.as_ref();
        if impure_callee(callee) {
            continue;
        }
        let bare = callee
            .rsplit('.')
            .next()
            .unwrap_or(callee)
            .to_ascii_lowercase();
        let pkg = callee
            .rsplit_once('.')
            .map(|(p, _)| p)
            .unwrap_or("")
            .to_ascii_lowercase();

        // Generic pool / map get-put is never a pure measure/parse helper.
        if is_pool_or_map_accessor(&bare, &pkg) {
            continue;
        }
        // stdlib / crypto Parse* and related are not cache-helper targets.
        // (PEM/x509 hot-path parse is PERF-231.)
        if is_excluded_parse_package(&pkg) {
            continue;
        }
        if !is_stable_arg_helper(&bare) {
            continue;
        }

        // Zero-arg pure-looking helpers (e.g. defaultProps()) — not Get/Load.
        if call.arguments.is_empty() || call.arguments.iter().all(|a| a.trim().is_empty()) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_230,
                file,
                line,
                col,
                "pure function is re-evaluated every iteration; hoist or cache",
                out,
            );
            emitted += 1;
            if emitted >= 6 {
                return;
            }
            continue;
        }

        // At least one arg is a simple ident/literal/field access that is not a
        // bare loop variable, so we still fire when config/style is mixed with
        // per-item text (cache-per-key opportunity).
        let mut any_stable = false;
        for arg in call.arguments.iter() {
            let a = arg.trim();
            if a.is_empty() {
                continue;
            }
            if is_loop_variant_name(a) {
                continue;
            }
            if is_simple_ident(a) || is_literal(a) {
                any_stable = true;
            } else if a.contains('.') {
                // field access like item.Props / cfg.Title — cacheable key
                any_stable = true;
            } else if a.contains('{') {
                // composite literal config — treated as stable shape
                any_stable = true;
            }
        }
        if !any_stable {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_230,
            file,
            line,
            col,
            "pure/helper call in loop has stable args; hoist or cache per distinct key",
            out,
        );
        emitted += 1;
        if emitted >= 6 {
            return;
        }
    }
}

/// Parse / measure / resolve / style helper names (portable English verbs).
fn is_stable_arg_helper(bare: &str) -> bool {
    if bare.contains("parseprops")
        || bare.contains("estimatetext")
        || bare.contains("gettextwidth")
        || bare.contains("textwidth")
        || bare.contains("text_width")
        || bare.contains("measuretext")
        || bare.contains("textmeasure")
        || bare.contains("resolvename")
        || bare.contains("resolveid")
        || bare.contains("parsehex")
        || bare.contains("parsestyle")
        || bare.contains("normalizeprops")
        || bare.contains("defaultprops")
    {
        return true;
    }
    bare.contains("parse")
        || bare.contains("measure")
        || bare.contains("estimate")
        || bare.contains("resolve")
        || bare.contains("normalize")
        || bare.contains("width")
        || bare.contains("props")
        || bare.contains("style")
        || bare.contains("lookup")
        || bare.starts_with("compute")
}

/// Packages whose Parse*/Decode* APIs must not be PERF-230 (stdlib or crypto).
fn is_excluded_parse_package(pkg: &str) -> bool {
    matches!(
        pkg,
        "time"
            | "strconv"
            | "url"
            | "json"
            | "xml"
            | "html"
            | "filepath"
            | "path"
            | "pem"
            | "x509"
            | "tls"
            | "asn1"
            | "base64"
            | "hex"
            | "mime"
            | "multipart"
            | "csv"
            | "template"
            | "text/template"
            | "html/template"
            | "flag"
            | "net"
            | "http"
            | "mail"
            | "smtp"
            | "crypto"
            | "rsa"
            | "ecdsa"
            | "ed25519"
    ) || pkg.ends_with("/pem")
        || pkg.ends_with("/x509")
        || pkg.ends_with("/json")
        || pkg.ends_with("/xml")
        || pkg.ends_with("/csv")
        || pkg.ends_with("/hex")
        || pkg.ends_with("/base64")
        || pkg.contains("encoding/")
}

/// `pool.Get`, `sync.Pool.Get`, `cache.Load`, bare Get/Load/Put/Store accessors.
fn is_pool_or_map_accessor(bare: &str, pkg: &str) -> bool {
    if matches!(
        bare,
        "get" | "load" | "put" | "store" | "delete" | "pop" | "push" | "take" | "borrow" | "return"
    ) {
        return true;
    }
    // package or receiver name suggests a pool
    if pkg == "pool"
        || pkg.ends_with("pool")
        || pkg.contains("pool")
        || pkg == "sync"
        || pkg.ends_with(".pool")
    {
        // only suppress when the method is a generic accessor, not GetTextWidth
        if matches!(
            bare,
            "get" | "load" | "put" | "store" | "new" | "getbuffer" | "getbytes"
        ) {
            return true;
        }
    }
    false
}

/// PERF-231: PEM Or Key Material Parsed On Hot Path
pub(crate) fn detect_perf_231(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let triggers = [
        "pem.Decode",
        "x509.ParseCertificate",
        "x509.ParsePKCS1PrivateKey",
        "x509.ParsePKCS8PrivateKey",
        "x509.ParseECPrivateKey",
        "tls.X509KeyPair",
        "tls.LoadX509KeyPair",
    ];

    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !triggers.contains(&callee) {
            continue;
        }
        if !is_hot_path(
            source,
            call.start_byte,
            &facts.source_index,
            is_in_loop(call),
        ) && !is_request_path(&facts.source_index)
        {
            // allow request-path whole-file only when also handler-shaped locally
            // already covered by is_hot_path; skip cold package init
            continue;
        }
        // Suppress obvious Once / package init
        if source.contains("sync.Once") && source.contains("Do(") {
            // still flag if call is outside Once body is hard; if Once present
            // and call not in hot name, skip — keep simple: Once + package var OK
            if !is_hot_path(
                source,
                call.start_byte,
                &facts.source_index,
                is_in_loop(call),
            ) {
                continue;
            }
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_231,
            file,
            line,
            col,
            "PEM/key material is parsed on a hot path; parse once at startup and reuse",
            out,
        );
        return;
    }
}

fn is_simple_ident(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

fn is_literal(s: &str) -> bool {
    s.starts_with('"')
        || s.starts_with('\'')
        || s.chars().all(|c| c.is_ascii_digit())
        || s == "true"
        || s == "false"
        || s == "nil"
}

fn is_loop_variant_name(a: &str) -> bool {
    matches!(
        a,
        "i" | "j"
            | "k"
            | "idx"
            | "index"
            | "v"
            | "val"
            | "value"
            | "item"
            | "cell"
            | "row"
            | "e"
            | "elem"
            | "it"
            | "n"
            | "x"
            | "y"
            | "p"
            | "c"
            | "r"
            | "s"
            | "t"
            | "b"
            | "ch"
            | "line"
            | "tok"
            | "token"
            | "page"
            | "node"
    )
}

fn impure_callee(callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    let bare = lower.rsplit('.').next().unwrap_or(lower.as_str());
    lower.contains("rand")
        || lower.contains("now")
        || lower.contains("read")
        || lower.contains("write")
        || lower.contains("next")
        || lower.contains("scan")
        || lower.contains("sleep")
        || lower.contains("lock")
        || lower.contains("unlock")
        // request / IO parsers — not pure measure/props helpers
        || bare.contains("parseform")
        || bare.contains("parsemultipart")
        || bare.contains("decodepem")
        || (bare == "decode" && (lower.starts_with("pem.") || lower.contains(".pem.")))
}

fn append_nil_clones(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for pattern in ["append([]byte(nil), ", "append([]byte{}, ", "append(nil, "] {
        let mut search = 0usize;
        while let Some(rel) = source[search..].find(pattern) {
            let start = search + rel;
            let arg_start = start + pattern.len();
            let rest = &source[arg_start..];
            // arg...
            if let Some(end) = rest.find("...") {
                let arg = rest[..end].trim();
                if is_simple_ident(arg) {
                    out.push((start, arg.to_string()));
                }
            }
            search = arg_start;
        }
    }
    out
}

fn window_has_recopy(window: &str) -> bool {
    let has_make = window.contains("make([]byte");
    let has_copy = window.contains("copy(");
    let has_clone = window.contains("slices.Clone(");
    // Require Len/len so small fixed makes (e.g. crypto scratch) near an
    // unrelated .Bytes() are not treated as post-producer re-copies.
    let make_from_len = window.contains(".Len()") || window.contains("len(");
    (has_make && has_copy && make_from_len) || has_clone
}

fn loop_has_parallel_fanout(loop_text: &str) -> bool {
    loop_text.contains(".Go(")
        || loop_text.contains("g.Go(")
        || loop_text.contains("group.Go(")
        || loop_text.contains("go func")
        || (loop_text.contains("wg.Add(") && loop_text.contains("go "))
        || (loop_text.contains("WaitGroup") && loop_text.contains("go "))
}

/// Names assigned from `name := []T{...}` / `name = []T{...}` with 1–2 elements.
fn tiny_composite_slice_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in source.lines() {
        let t = line.trim();
        let Some(eq) = t.find(":=").or_else(|| t.find('=')) else {
            continue;
        };
        let lhs = t[..eq].trim().trim_end_matches(':').trim();
        let rhs = t[eq..]
            .trim_start_matches(':')
            .trim_start_matches('=')
            .trim();
        if !is_simple_ident(lhs) {
            continue;
        }
        if let Some(n) = composite_literal_elem_count(rhs) {
            if (1..=2).contains(&n) {
                names.push(lhs.to_string());
            }
        }
    }
    names
}

fn range_target_name(loop_text: &str) -> Option<&str> {
    let idx = loop_text.find("range")?;
    let rest = loop_text[idx + "range".len()..].trim_start();
    let name = rest
        .split(|c: char| c == '{' || c.is_whitespace())
        .next()?
        .trim();
    if is_simple_ident(name) {
        Some(name)
    } else {
        None
    }
}

fn composite_elem_count_after_range(loop_text: &str) -> Option<usize> {
    let idx = loop_text.find("range")?;
    let rest = loop_text[idx + "range".len()..].trim_start();
    composite_literal_elem_count(rest)
}

/// Count elements in a leading `[]T{...}` / `[]pkg.T{...}` composite literal.
fn composite_literal_elem_count(s: &str) -> Option<usize> {
    let s = s.trim_start();
    if !s.starts_with('[') {
        return None;
    }
    let brace = s.find('{')?;
    let after = &s[brace + 1..];
    let close = after.find('}')?;
    let inner = after[..close].trim();
    if inner.is_empty() {
        return Some(0);
    }
    // Rough element count: top-level commas (no nested composites in fixtures).
    let n = inner.split(',').filter(|p| !p.trim().is_empty()).count();
    Some(n)
}

fn continue_name_from_source(source: &str, start_byte: usize) -> Option<&str> {
    let window_start = char_boundary(source, start_byte.saturating_sub(40));
    let window = &source[window_start..start_byte.min(source.len())];
    // look for `name :=` or `name =`
    let line = window.lines().last()?;
    let line = line.trim();
    let name = line
        .split(":=")
        .next()
        .or_else(|| line.split('=').next())?
        .trim();
    if is_simple_ident(name) {
        Some(name)
    } else {
        None
    }
}
