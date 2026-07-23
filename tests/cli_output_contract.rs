use std::process::Command;

fn command(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_codehound"))
        .args(args)
        .output()
        .expect("run codehound")
}

#[test]
fn no_terminal_rejects_machine_formats_instead_of_emitting_text() {
    for (format, expected) in [("json", "JSON"), ("sarif", "SARIF")] {
        let output = command(&["--format", format, "--no-terminal"]);
        assert!(
            !output.status.success(),
            "{format} invocation unexpectedly succeeded"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "stderr: {stderr}");
    }
}

#[test]
fn output_modifiers_require_their_machine_format() {
    for (argument, expected) in [
        ("--sarif-compact", "requires --format sarif"),
        ("--json-envelope", "requires --format json"),
    ] {
        let output = command(&[argument]);
        assert!(
            !output.status.success(),
            "{argument} unexpectedly succeeded"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "stderr: {stderr}");
    }
}

#[test]
fn no_terminal_retains_its_text_summary_contract() {
    let root = std::env::temp_dir().join(format!(
        "codehound-cli-output-contract-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create empty scan root");

    let output = command(&[
        "--no-terminal",
        "--no-cache",
        root.to_str().expect("utf-8 path"),
    ]);
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("no slop detected"),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn no_terminal_rejects_format_modifiers_even_with_text_default() {
    for argument in ["--sarif-compact", "--json-envelope"] {
        let output = command(&["--no-terminal", argument]);
        assert!(
            !output.status.success(),
            "{argument} with --no-terminal unexpectedly succeeded"
        );
    }
}
