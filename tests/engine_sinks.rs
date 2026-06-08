use slopguard::engine::sinks;

#[test]
fn path_traversal_sinks_contain_expected() {
    assert!(sinks::matches_sink(
        &sinks::PATH_TRAVERSAL_SINKS,
        "os.ReadFile"
    ));
    assert!(sinks::matches_sink(
        &sinks::PATH_TRAVERSAL_SINKS,
        "ioutil.ReadFile"
    ));
    assert!(!sinks::matches_sink(
        &sinks::PATH_TRAVERSAL_SINKS,
        "os.Open"
    ));
}

#[test]
fn sql_sinks_contain_expected() {
    for sink in &[
        "db.Query",
        "db.QueryRow",
        "db.Exec",
        "db.QueryContext",
        "db.QueryRowContext",
        "db.ExecContext",
    ] {
        assert!(
            sinks::matches_sink(&sinks::SQL_SINKS, sink),
            "expected SQL sink: {sink}"
        );
    }
    assert!(!sinks::matches_sink(&sinks::SQL_SINKS, "exec.Command"));
}

#[test]
fn command_injection_sinks_contain_expected() {
    assert!(sinks::matches_sink(
        &sinks::COMMAND_INJECTION_SINKS,
        "exec.Command"
    ));
    assert!(sinks::matches_sink(
        &sinks::COMMAND_INJECTION_SINKS,
        "exec.CommandContext"
    ));
    assert!(!sinks::matches_sink(
        &sinks::COMMAND_INJECTION_SINKS,
        "os.ReadFile"
    ));
}

#[test]
fn link_resolution_sinks_contain_expected() {
    assert!(sinks::matches_sink(
        &sinks::LINK_RESOLUTION_SINKS,
        "os.Open"
    ));
    assert!(sinks::matches_sink(
        &sinks::LINK_RESOLUTION_SINKS,
        "os.OpenFile"
    ));
}
