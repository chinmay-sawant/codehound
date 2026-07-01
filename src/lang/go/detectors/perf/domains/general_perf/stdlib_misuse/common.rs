//! Shared helpers used by multiple stdlib_misuse sub-files.
//!
//! All helpers are `pub(crate)` so sibling modules under
//! `stdlib_misuse/` can access them via `super::common::*`.

use crate::core::ParsedUnit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageLevelCache {
    pub(crate) name: String,
    pub(crate) byte: usize,
    pub(crate) is_sync_map: bool,
}

/// PERF-115/116/117 helper: pull the source text starting at a
/// byte offset, capped to the same line. Used to look for the
/// trailing `== 0` / `!= -1` patterns without indexing past the
/// end of the line.
pub(crate) fn call_text(unit: &ParsedUnit, start: usize) -> &str {
    let source = unit.source.as_ref();
    let start = start.min(source.len());
    let end = source.len().min(start + 64);
    // Trim to end-of-line so we don't pick up the next statement.
    let line_end = source[start..end]
        .find('\n')
        .map(|i| start + i)
        .unwrap_or(end);
    &source[start..line_end]
}

pub(crate) fn is_log_call(callee: &str) -> bool {
    matches!(
        callee,
        "log.Print"
            | "log.Printf"
            | "log.Println"
            | "log.Fatal"
            | "log.Fatalf"
            | "log.Panic"
            | "log.Panicf"
            | "log.Error"
            | "log.Errorf"
            | "log.Warn"
            | "log.Warnf"
            | "log.Info"
            | "log.Infof"
            | "log.Debug"
            | "log.Debugf"
    )
}

pub(crate) fn extract_first_quoted(s: &str) -> &str {
    let open = s.find('"');
    let Some(open) = open else { return "" };
    let rest = &s[open + 1..];
    let close = rest.find('"');
    let Some(close) = close else { return "" };
    &rest[..close]
}

pub(crate) fn fmt_contains_verb(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Skip %% which is an escaped percent.
            if i + 1 < bytes.len() && bytes[i + 1] == b'%' {
                i += 2;
                continue;
            }
            // A real verb follows: at least one ASCII letter
            // (the verb specifier) before a non-identifier byte.
            if i + 1 < bytes.len() && bytes[i + 1].is_ascii_alphabetic() {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Returns the method name of a call fact's callee expression.
/// For `m.Store` returns `Store`; for `runtime.SetFinalizer` returns
/// `SetFinalizer`; for a bare identifier it returns the same name.
pub(crate) fn method_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee)
}

pub(crate) fn is_simple_ident(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(crate) fn body_has_io(body: &str) -> bool {
    // Match the common packages whose calls take a context as
    // the first argument. The detector only checks substrings.
    const PACKAGES: &[&str] = &[
        "http.", "db.", "sql.", "redis.", "rdb.", "client.", "store.", "queue.", "kafka.",
    ];
    PACKAGES.iter().any(|p| body.contains(p))
}

pub(crate) fn package_level_caches(source: &str) -> Vec<PackageLevelCache> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_var_block = false;
    let mut byte = 0usize;

    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let indent = line.len().saturating_sub(trimmed.len());
        let trimmed_byte = byte + indent;

        if depth == 0 {
            if in_var_block {
                if trimmed.starts_with(')') {
                    in_var_block = false;
                } else if let Some(cache) = parse_cache_decl_line(trimmed, trimmed_byte, false) {
                    out.push(cache);
                }
            } else if trimmed.starts_with("var (") {
                in_var_block = true;
            } else if let Some(cache) = parse_cache_decl_line(trimmed, trimmed_byte, true) {
                out.push(cache);
            }
        }

        depth += line.chars().filter(|&c| c == '{').count() as i32;
        depth -= line.chars().filter(|&c| c == '}').count() as i32;
        byte += line.len();
    }

    out
}

pub(crate) fn cache_has_eviction_bound(source: &str, name: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    let name_lower = name.to_ascii_lowercase();
    let direct_patterns = [
        format!("len({name}) >"),
        format!("len({name}) >="),
        format!("cap({name}) >"),
        format!("cap({name}) >="),
        format!("clear({name})"),
        format!("delete({name},"),
        format!("{name}.delete("),
        format!("{name}.loadanddelete("),
    ];
    if direct_patterns
        .iter()
        .any(|pattern| lower.contains(&pattern.to_ascii_lowercase()))
    {
        return true;
    }

    // ponytail: coarse TTL/expiry heuristic. Ceiling: file-level textual
    // matching can miss helper-mediated eviction or misread unrelated time
    // code. Upgrade path: bind the cache variable to its enclosing function
    // and walk the actual condition/control-flow nodes.
    let time_markers = [
        "ttl",
        "expire",
        "expires",
        "expiry",
        "evict",
        "eviction",
        "time.now(",
        "time.since(",
        ".before(",
        ".after(",
        "ticker",
        "timer",
    ];
    source.lines().any(|line| {
        let line_lower = line.to_ascii_lowercase();
        line_lower.contains(&name_lower)
            && time_markers
                .iter()
                .any(|marker| line_lower.contains(marker))
    })
}

fn parse_cache_decl_line(
    line: &str,
    byte: usize,
    expect_var_prefix: bool,
) -> Option<PackageLevelCache> {
    let rest = if expect_var_prefix {
        line.strip_prefix("var ")?
    } else {
        line
    };
    let mut parts = rest.split_whitespace();
    let name = parts.next()?.trim_end_matches(',');
    if !is_simple_ident(name) {
        return None;
    }
    let is_sync_map = rest.contains("sync.Map");
    let is_plain_map = rest.contains("map[");
    if !is_sync_map && !is_plain_map {
        return None;
    }
    Some(PackageLevelCache {
        name: name.to_string(),
        byte,
        is_sync_map,
    })
}

#[cfg(test)]
mod tests {
    use super::{cache_has_eviction_bound, package_level_caches};

    #[test]
    fn package_level_caches_finds_top_level_var_specs() {
        let source = r#"
package sample

var renderCache = map[string]int{}

var (
    memo sync.Map
    ignored int
)

func useIt() {
    localCache := map[string]int{}
    _ = localCache
}
"#;
        let caches = package_level_caches(source);
        assert_eq!(caches.len(), 2);
        assert_eq!(caches[0].name, "renderCache");
        assert!(!caches[0].is_sync_map);
        assert_eq!(caches[1].name, "memo");
        assert!(caches[1].is_sync_map);
    }

    #[test]
    fn cache_has_eviction_bound_detects_size_and_time_patterns() {
        let len_bound = r#"
if len(renderCache) > 1000 {
    clear(renderCache)
}
"#;
        assert!(cache_has_eviction_bound(len_bound, "renderCache"));

        let cap_bound = r#"
if cap(renderCache) >= maxEntries {
    renderCache = renderCache[:0]
}
"#;
        assert!(cache_has_eviction_bound(cap_bound, "renderCache"));

        let ttl_bound = r#"
if renderCacheExpiry.Before(time.Now()) {
    delete(renderCache, key)
}
"#;
        assert!(cache_has_eviction_bound(ttl_bound, "renderCache"));
    }
}
