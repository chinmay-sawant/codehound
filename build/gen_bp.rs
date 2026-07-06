use std::collections::BTreeMap;

use crate::types::JsonRule;

pub fn generate_go_bp_metadata_code(
    rule_map: &BTreeMap<u32, JsonRule>,
    supported_ids: &[u32],
) -> String {
    crate::gen_metadata::generate_go_bp_metadata_code(rule_map, supported_ids)
}
