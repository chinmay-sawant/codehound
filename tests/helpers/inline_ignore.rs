//! Shared test helpers for inline-ignore tests.

use std::time::{SystemTime, UNIX_EPOCH};

pub fn unique_temp_root(test_name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("slopguard-{test_name}-{unique}"))
}

pub fn write_vulnerable_go(path: &std::path::Path, ignore: &str) {
    std::fs::write(
        path,
        format!(
            r#"package sample

import (
	"net/http"
	"os/exec"
)

func TraceRoute(w http.ResponseWriter, r *http.Request) {{
	host := r.URL.Query().Get("host")
	{ignore}
	cmd := exec.Command("sh", "-c", "traceroute -m 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {{
		http.Error(w, string(out), http.StatusBadRequest)
		return
	}}
	_, _ = w.Write(out)
}}
"#
        ),
    )
    .unwrap();
}

pub fn write_vulnerable_go_with_header(path: &std::path::Path, header: &str) {
    std::fs::write(
        path,
        format!(
            r#"{header}package sample

import (
	"net/http"
	"os/exec"
)

func TraceRoute(w http.ResponseWriter, r *http.Request) {{
	host := r.URL.Query().Get("host")
	cmd := exec.Command("sh", "-c", "traceroute -m 1 "+host)
	out, err := cmd.CombinedOutput()
	if err != nil {{
		http.Error(w, string(out), http.StatusBadRequest)
		return
	}}
	w.Write(out)
}}
"#
        ),
    )
    .unwrap();
}
