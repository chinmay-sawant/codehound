use slopguard::engine::sinks;

#[test]
fn sink_matching_is_correct() {
    for (sink_table, positive, negative) in [
        (
            &sinks::PATH_TRAVERSAL_SINKS,
            &["os.ReadFile", "ioutil.ReadFile"] as &[&str],
            &["os.Open"] as &[&str],
        ),
        (
            &sinks::SQL_SINKS,
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
            &sinks::COMMAND_INJECTION_SINKS,
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
            assert!(sinks::matches_sink(sink_table, s), "expected match: {s}");
        }
        for s in negative {
            assert!(
                !sinks::matches_sink(sink_table, s),
                "expected no match: {s}"
            );
        }
    }
}
