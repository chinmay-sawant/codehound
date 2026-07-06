use phf::phf_set;
use codehound::engine::sinks;

static SQL_SINKS: phf::Set<&'static str> = phf_set! {
    "db.Query",
    "db.QueryRow",
    "db.Exec",
    "db.QueryContext",
    "db.QueryRowContext",
    "db.ExecContext",
};

static COMMAND_INJECTION_SINKS: phf::Set<&'static str> = phf_set! {
    "exec.Command",
    "exec.CommandContext",
};

#[test]
fn sink_matching_is_correct() {
    for (sink_table, positive, negative) in [
        (
            &sinks::PATH_TRAVERSAL_SINKS,
            &["os.ReadFile", "ioutil.ReadFile"] as &[&str],
            &["os.Open"] as &[&str],
        ),
        (
            &SQL_SINKS,
            &[
                "db.Query",
                "db.QueryRow",
                "db.Exec",
                "db.QueryContext",
                "db.QueryRowContext",
                "db.ExecContext",
            ],
            &["exec.Command"],
        ),
        (
            &COMMAND_INJECTION_SINKS,
            &["exec.Command", "exec.CommandContext"],
            &["os.ReadFile"],
        ),
        (
            &sinks::LINK_RESOLUTION_SINKS,
            &["os.Open", "os.OpenFile"],
            &[],
        ),
    ] {
        for s in positive {
            assert!(sink_table.contains(s), "expected match: {s}");
        }
        for s in negative {
            assert!(!sink_table.contains(s), "expected no match: {s}");
        }
    }
}
