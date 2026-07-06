use std::borrow::Cow;

use codehound::engine::AnalysisResult;
use codehound::rules::{Finding, FindingInputs, LineCol, Severity};

#[path = "helpers/mod.rs"]
mod helpers;

use insta::assert_snapshot;
use codehound::reporting::sarif::render_to_string;

fn sample_result() -> AnalysisResult {
    helpers::reporting::sample_result(vec![
        Finding::new(FindingInputs::new(
            "CWE-22",
            "Path traversal",
            "a.go",
            LineCol { line: 1, column: 1 },
            "msg",
            Severity::High,
            Cow::Borrowed(&[]),
        )),
        Finding::new(FindingInputs::new(
            "CWE-89",
            "SQL injection",
            "b.go",
            LineCol { line: 2, column: 3 },
            "msg2",
            Severity::Critical,
            Cow::Borrowed(&[]),
        )),
    ])
}

fn redact_sarif_timestamps(mut s: String) -> String {
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&s) {
        if let Some(runs) = v.get_mut("runs").and_then(|r| r.as_array_mut()) {
            for run in runs {
                if let Some(invocations) = run.get_mut("invocations").and_then(|i| i.as_array_mut())
                {
                    for inv in invocations {
                        if let Some(obj) = inv.as_object_mut() {
                            obj.remove("endTimeUtc");
                        }
                    }
                }
                if let Some(tool) = run.get_mut("tool").and_then(|t| t.as_object_mut()) {
                    if let Some(driver) = tool.get_mut("driver").and_then(|d| d.as_object_mut()) {
                        driver.remove("version");
                        driver.remove("semanticVersion");
                    }
                }
            }
        }
        s = serde_json::to_string_pretty(&v).unwrap();
    }
    s
}

#[test]
fn sarif_log_snapshot_is_stable() {
    let sample = sample_result();
    let raw = render_to_string(&sample).unwrap();
    let s = redact_sarif_timestamps(raw);
    assert_snapshot!("sarif_log", s);
}
