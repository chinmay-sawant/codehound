#[test]
fn golang_ruleset_contains_perf_101_through_212() {
    let dir = std::path::Path::new("ruleset/golang/chunks");
    let mut object = serde_json::Map::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .expect("read ruleset chunk dir")
        .map(|entry| entry.expect("read chunk entry"))
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let path = entry.path();
        let text = std::fs::read_to_string(&path).expect("read ruleset chunk");
        let value: serde_json::Value = serde_json::from_str(&text).expect("parse ruleset chunk");
        let chunk = value.as_object().expect("ruleset chunk top-level object");
        for (rule_id, rule) in chunk {
            assert!(
                object.insert(rule_id.clone(), rule.clone()).is_none(),
                "duplicate rule id across chunks: {rule_id}"
            );
        }
    }

    let missing: Vec<String> = (101..=212)
        .map(|id| format!("PERF-{id}"))
        .filter(|rule_id| !object.contains_key(rule_id))
        .collect();

    assert!(
        missing.is_empty(),
        "ruleset/golang/chunks is missing PERF entries: {missing:?}"
    );
}
