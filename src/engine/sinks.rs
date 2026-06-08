use phf::phf_set;

pub static PATH_TRAVERSAL_SINKS: phf::Set<&'static str> = phf_set! {
    "os.ReadFile",
    "ioutil.ReadFile",
};

pub static SQL_SINKS: phf::Set<&'static str> = phf_set! {
    "db.Query",
    "db.QueryRow",
    "db.Exec",
    "db.QueryContext",
    "db.QueryRowContext",
    "db.ExecContext",
};

pub static COMMAND_INJECTION_SINKS: phf::Set<&'static str> = phf_set! {
    "exec.Command",
    "exec.CommandContext",
};

pub static FILE_WRITE_SINKS: phf::Set<&'static str> = phf_set! {
    "os.WriteFile",
    "os.Create",
    "ioutil.WriteFile",
};

pub static CONFIG_SINKS: phf::Set<&'static str> = phf_set! {
    "sql.Open",
};

pub static LINK_RESOLUTION_SINKS: phf::Set<&'static str> = phf_set! {
    "os.Open",
    "os.OpenFile",
};

pub static FILE_OPEN_SINKS: phf::Set<&'static str> = phf_set! {
    "os.Open",
    "os.OpenFile",
};

/// Check if a callee name matches any sink in the set.
pub fn matches_sink(sinks: &phf::Set<&'static str>, callee: &str) -> bool {
    sinks.contains(callee)
}
