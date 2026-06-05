use slopguard::cwe::{
    CWE_CATALOG, CWE_REFS_400_1336, CWE_REFS_407, CWE_REFS_770, CWE_REFS_770_400,
    builtin_rule_catalogue, default_ruleset_path,
};

#[test]
fn catalog_entries_are_ordered() {
    assert_eq!(CWE_CATALOG[0].id, 400);
    assert_eq!(CWE_CATALOG[1].id, 405);
    assert_eq!(CWE_CATALOG[2].id, 407);
    assert_eq!(CWE_CATALOG[3].id, 770);
    assert_eq!(CWE_CATALOG[4].id, 1336);
    assert_eq!(CWE_CATALOG[5].id, 1041);
}

#[test]
fn ref_slices_have_correct_lengths() {
    assert_eq!(CWE_REFS_400_1336.len(), 2);
    assert_eq!(CWE_REFS_407.len(), 1);
    assert_eq!(CWE_REFS_770.len(), 1);
    assert_eq!(CWE_REFS_770_400.len(), 2);
}

#[test]
fn default_ruleset_path_is_under_workspace() {
    let p = default_ruleset_path();
    assert!(p.ends_with("ruleset/golang/golang.json"));
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
