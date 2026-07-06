use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_412(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let client_lock_path =
        facts.source_index.has("lockfile") && facts.source_index.has("os.ReadFile(lockPath)");
    if !client_lock_path {
        return;
    }
    if facts.source_index.has_any(&["jobLockPath", "fixedJobLock"]) {
        return;
    }

    let start_byte = source.find("lockfile").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_412,
        file,
        line,
        col,
        "the lock file path comes directly from the client request",
        out,
    );
}

pub(crate) fn detect_cwe_1289(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let literal_path_block = (facts
        .source_index
        .has_any(&["FetchSharedAsset(", "FetchSharedAssetPure("]))
        && facts.source_index.has(r#"requested == "private/keys.pem""#)
        && facts.source_index.has("filepath.Join(root, requested)");
    if !literal_path_block {
        return;
    }
    if facts.source_index.has_any(&[
        "filepath.Clean(filepath.Join(root, requested))",
        "HasPrefix(clean, root+string(filepath.Separator))",
    ]) {
        return;
    }

    let start_byte = source
        .find("requested == \"private/keys.pem\"")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1289,
        file,
        line,
        col,
        "asset access relies on a literal blocked path comparison before canonical normalization",
        out,
    );
}
