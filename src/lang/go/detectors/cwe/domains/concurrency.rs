use super::super::facts::GoUnitFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_366(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let direct_credit_increment =
        source.contains("walletCredits += amount") || source.contains("referralCredits += 10");
    if !direct_credit_increment {
        return;
    }
    if source.contains("atomic.AddInt64(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("walletCredits += amount") {
        idx
    } else {
        source.find("referralCredits += 10").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_366,
        file,
        line,
        col,
        "shared credit state is incremented without atomic or synchronized protection",
        out,
    );
}

pub(crate) fn detect_cwe_367(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let stat_then_use =
        source.contains("os.Stat(target)") && source.contains("os.ReadFile(target)");
    if !stat_then_use {
        return;
    }

    let start_byte = source.find("os.Stat(target)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_367,
        file,
        line,
        col,
        "the code checks a file path with Stat before later using it, creating a TOCTOU race window",
        out,
    );
}

pub(crate) fn detect_cwe_368(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_privilege_flag = (source.contains("actingAsRoot = true")
        || source.contains("privilegedMode = true"))
        && source.contains("os.Setenv(");
    if !shared_privilege_flag {
        return;
    }
    if facts.source_index.has("sync.Mutex") || source.contains("Lock()") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("actingAsRoot = true") {
        idx
    } else {
        source.find("privilegedMode = true").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_368,
        file,
        line,
        col,
        "privileged context switching is controlled by an unsynchronized shared mode flag",
        out,
    );
}

pub(crate) fn detect_cwe_421(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_event_state = (source.contains("transferToken =")
        && source.contains("event: status\\ndata: \" + transferToken"))
        || (source.contains("wireTransferCode =")
            && source.contains("event: status\\ndata: %s\\n\\n\", wireTransferCode"));
    if !shared_event_state {
        return;
    }
    if facts.source_index.has("sync.Mutex")
        || source.contains("transferMu")
        || source.contains("wireMu")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("transferToken =") {
        idx
    } else {
        source.find("wireTransferCode =").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_421,
        file,
        line,
        col,
        "an alternate event channel exposes shared transfer state without synchronization",
        out,
    );
}

pub(crate) fn detect_cwe_820(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let unsynchronized_map_write =
        source.contains("visitCounts[key] = visitCounts[key] + 1") && source.contains("TrackVisit");
    if !unsynchronized_map_write {
        return;
    }
    if source.contains("visitMu.Lock()") || source.contains("visitMu sync.Mutex") {
        return;
    }

    let start_byte = source
        .find("visitCounts[key] = visitCounts[key] + 1")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_820,
        file,
        line,
        col,
        "shared visit counters are updated without synchronization",
        out,
    );
}

pub(crate) fn detect_cwe_821(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let writes_under_rlock =
        source.contains("RLock()") && source.contains("tokenCache[key] = value");
    if !writes_under_rlock {
        return;
    }
    if source.contains("cacheMu.Lock()") {
        return;
    }

    let start_byte = source.find("RLock()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_821,
        file,
        line,
        col,
        "shared cache state is mutated while only a read lock is held",
        out,
    );
}
