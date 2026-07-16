//! Single-pass substring index for Go bad-practice detector hot paths.

/// Frequently scanned literals across the Go bad-practice bundle (one `contains` per needle).
///
/// Keep this list to tokens used as **necessary conditions** for short-circuiting
/// rule entry (Phase 1). Prefer shared tokens over one-off phrases.
pub const NEEDLES: &[&str] = &[
    // assignment / error discard (BP-1 and friends)
    "_",
    ":=",
    // control-flow / concurrency
    "defer",
    "defer ",
    "go func",
    "select",
    "make(chan",
    "recover()",
    "panic(",
    "context.",
    "sync.",
    "sync.Mutex",
    " sync.Mutex",
    ".Add(",
    ".Unlock()",
    "time.After",
    "time.Sleep",
    "context.Background",
    // logging / reporting
    "log.",
    "Logger.",
    ".Error(",
    ".Warn(",
    "fmt.Printf(",
    "fmt.Fprintf(",
    // HTTP / servers
    "http.Server",
    "http.",
    "ListenAndServe",
    "gin.",
    "echo.",
    "fiber.",
    "chi.",
    // data / SQL
    "sql.",
    "sqlx.",
    "gorm",
    "Query(",
    "Exec(",
    // process / config
    "os.Exit",
    "signal.",
    "flag.",
    // testing
    "testing.",
    "Test",
    "t.Error",
    "t.Fatal",
    "t.Run",
    // misc high-frequency
    "errors.",
    "init(",
    "interface{",
];

pub use crate::lang::source_index::SourceIndex;
