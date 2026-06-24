#[test]
fn golang_ruleset_contains_perf_101_through_212() {
    let text = std::fs::read_to_string("ruleset/golang/golang.json").expect("read ruleset");
    let value: serde_json::Value = serde_json::from_str(&text).expect("parse ruleset json");
    let object = value.as_object().expect("ruleset top-level object");

    let missing: Vec<String> = (101..=212)
        .map(|id| format!("PERF-{id}"))
        .filter(|rule_id| !object.contains_key(rule_id))
        .collect();

    assert!(
        missing.is_empty(),
        "ruleset/golang/golang.json is missing PERF entries: {missing:?}"
    );
}
