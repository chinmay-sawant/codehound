use slopguard::cwe::{
    CWE_CATALOG, CWE_REFS_400_1336, builtin_rule_catalogue, default_ruleset_path,
};

#[test]
fn catalog_has_expected_entries() {
    let ids: Vec<u32> = CWE_CATALOG.iter().map(|c| c.id).collect();
    // Catalog is now generated from chunked ruleset JSON — contains all CWE entries
    assert!(
        ids.len() > 100,
        "expected >100 CWE entries, got {}",
        ids.len()
    );
    // Verify key CWE entries exist (order not guaranteed)
    assert!(ids.contains(&15));
    assert!(ids.contains(&22));
    assert!(ids.contains(&78));
    assert!(ids.contains(&79));
    assert!(ids.contains(&89));
    assert!(ids.contains(&90));
}

#[test]
fn ref_slices_have_correct_lengths() {
    assert_eq!(CWE_REFS_400_1336.len(), 2);
}

#[test]
fn default_ruleset_path_is_under_workspace() {
    let p = default_ruleset_path();
    assert!(p.ends_with("ruleset/golang/chunks"));
}

#[test]
fn builtin_catalogue_has_all_entries() {
    let cat = builtin_rule_catalogue();
    assert!(cat.len() > 100, "expected >100 rules, got {}", cat.len());

    for entry in cat {
        assert!(!entry.id.is_empty(), "rule has empty id");
        assert!(!entry.name.is_empty(), "rule {:?} has empty name", entry.id);
    }
}
