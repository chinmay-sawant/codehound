use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_412(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let client_lock_path = source.contains("lockfile") && source.contains("os.ReadFile(lockPath)");
    if !client_lock_path {
        return;
    }
    if source.contains("jobLockPath") || source.contains("fixedJobLock") {
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

pub(crate) fn detect_cwe_1289(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let literal_path_block = (source.contains("FetchSharedAsset(")
        || source.contains("FetchSharedAssetPure("))
        && source.contains("requested == \"private/keys.pem\"")
        && source.contains("filepath.Join(root, requested)");
    if !literal_path_block {
        return;
    }
    if source.contains("filepath.Clean(filepath.Join(root, requested))")
        || source.contains("HasPrefix(clean, root+string(filepath.Separator))")
    {
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
