use phf::phf_set;

pub static PATH_TRAVERSAL_SINKS: phf::Set<&'static str> = phf_set! {
    "os.ReadFile",
    "ioutil.ReadFile",
};

#[cfg(test)]
pub static SQL_SINKS: phf::Set<&'static str> = phf_set! {
    "db.Query",
    "db.QueryRow",
    "db.Exec",
    "db.QueryContext",
    "db.QueryRowContext",
    "db.ExecContext",
};

#[cfg(test)]
pub static COMMAND_INJECTION_SINKS: phf::Set<&'static str> = phf_set! {
    "exec.Command",
    "exec.CommandContext",
};

pub static CONFIG_SINKS: phf::Set<&'static str> = phf_set! {
    "sql.Open",
    "factory",
};

pub static LINK_RESOLUTION_SINKS: phf::Set<&'static str> = phf_set! {
    "os.Open",
    "os.OpenFile",
};
