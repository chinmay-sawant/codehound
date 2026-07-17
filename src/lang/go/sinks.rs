//! Perfect-hash callee tables for Go sink classification.

use phf::phf_set;

/// Callees treated as path-traversal sinks.
pub static PATH_TRAVERSAL_SINKS: phf::Set<&'static str> = phf_set! {
    "os.ReadFile",
    "ioutil.ReadFile",
};

/// SQL query/exec callees used by unit tests for sink classification.
#[cfg(test)]
pub static SQL_SINKS: phf::Set<&'static str> = phf_set! {
    "db.Query",
    "db.QueryRow",
    "db.Exec",
    "db.QueryContext",
    "db.QueryRowContext",
    "db.ExecContext",
};

/// Command-execution callees used by unit tests for sink classification.
#[cfg(test)]
pub static COMMAND_INJECTION_SINKS: phf::Set<&'static str> = phf_set! {
    "exec.Command",
    "exec.CommandContext",
};

/// Callees treated as configuration / connection-string sinks.
pub static CONFIG_SINKS: phf::Set<&'static str> = phf_set! {
    "sql.Open",
    "factory",
};

/// Callees that resolve filesystem links or open files by path.
pub static LINK_RESOLUTION_SINKS: phf::Set<&'static str> = phf_set! {
    "os.Open",
    "os.OpenFile",
};
