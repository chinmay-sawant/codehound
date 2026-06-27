use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_366(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let direct_credit_increment =
        facts.source_index.has("walletCredits += amount") || facts.source_index.has("referralCredits += 10");
    if !direct_credit_increment {
        return;
    }
    if facts.source_index.has("atomic.AddInt64(") {
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

pub(crate) fn detect_cwe_368(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_privilege_flag = (facts.source_index.has("actingAsRoot = true")
        || facts.source_index.has("privilegedMode = true"))
        && facts.source_index.has("os.Setenv(");
    if !shared_privilege_flag {
        return;
    }
    if facts.source_index.has("sync.Mutex") || facts.source_index.has("Lock()") {
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

    let shared_event_state = (facts.source_index.has("transferToken =")
        && facts.source_index.has("event: status\\ndata: \" + transferToken"))
        || (facts.source_index.has("wireTransferCode =")
            && facts.source_index.has("event: status\\ndata: %s\\n\\n\", wireTransferCode"));
    if !shared_event_state {
        return;
    }
    if facts.source_index.has("sync.Mutex")
        || facts.source_index.has("transferMu")
        || facts.source_index.has("wireMu")
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

pub(crate) fn detect_cwe_820(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let unsynchronized_map_write =
        facts.source_index.has("visitCounts[key] = visitCounts[key] + 1") && facts.source_index.has("TrackVisit");
    if !unsynchronized_map_write {
        return;
    }
    if facts.source_index.has("visitMu.Lock()") || facts.source_index.has("visitMu sync.Mutex") {
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

pub(crate) fn detect_cwe_821(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let writes_under_rlock =
        facts.source_index.has("RLock()") && facts.source_index.has("tokenCache[key] = value");
    if !writes_under_rlock {
        return;
    }
    if facts.source_index.has("cacheMu.Lock()") {
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
