use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Concurrency residual C3 trust freeze (concurrency/shared_state.rs).
// Rules: CWE-366, CWE-368, CWE-421, CWE-820, CWE-821.
// Selected over toctou.rs (CWE-367) which already has a dated Heuristic disposition
// (§2.8 / call-facts Stat+ReadFile). Do not infer channel/goroutine data flow or
// lifecycle ownership. Proposed dispositions: fixture-only for all five.
// See plans/v0.0.5/pr-cwe-trust-concurrency-residual.md.

/// CWE-366 — Race Condition within a Thread.
///
/// Freeze (C3 / #114): primary evidence is exact SI credit-increment museum
/// (`walletCredits += amount` frameworks / `referralCredits += 10` stdlib) without
/// `atomic.AddInt64(`. No production-shaped call-facts primary is safe: non-atomic
/// `+=` is not a callee, and generalizing shared-int mutation would require
/// concurrent-access proof (goroutine/handler lifecycle) which is out of scope.
///
/// Negatives: SI `atomic.AddInt64(` (safe fixtures replace the compound assign).
/// Disposition: **fixture-only** (identifier museum; not structural).
pub(crate) fn detect_cwe_366(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (SI museum): exact corpus credit increments. Not generalized
    // shared-int mutation — that needs concurrent-access proof we do not claim.
    let direct_credit_increment = facts.source_index.has("walletCredits += amount")
        || facts.source_index.has("referralCredits += 10");
    if !direct_credit_increment {
        return;
    }
    // Negative gate: atomic update replaces the racy compound assignment.
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

/// CWE-368 — Context Switching Race Condition.
///
/// Freeze (C3 / #114): real sink is `os.Setenv` (process-global env write) co-used
/// with a corpus privilege-mode flag (`actingAsRoot = true` / `privilegedMode = true`)
/// and without mutex protection. Call-facts become primary for the Setenv sink;
/// privilege-flag identifiers remain SI co-signals (not a general principal-switch
/// analysis). Negatives: SI `sync.Mutex` or `Lock()`.
///
/// Disposition: **fixture-only** (sink is production-shaped; emit still gated on
/// corpus mode-flag names). Do not infer goroutine ownership of the flag.
pub(crate) fn detect_cwe_368(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: corpus privilege-mode flag + Setenv token.
    let shared_privilege_flag = (facts.source_index.has("actingAsRoot = true")
        || facts.source_index.has("privilegedMode = true"))
        && facts.source_index.has("os.Setenv(");
    if !shared_privilege_flag {
        return;
    }
    // Negative gate: synchronized privilege context (mutex present in unit).
    if facts.source_index.has("sync.Mutex") || facts.source_index.has("Lock()") {
        return;
    }

    // Primary signal: call facts — os.Setenv (process-global env write) co-present
    // with the SI privilege-flag museum above. Span at Setenv call site.
    let Some(setenv_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Setenv")
    else {
        return;
    };

    let (line, col) = unit.line_col(setenv_call.start_byte);
    emit::push_finding(
        &META_CWE_368,
        file,
        line,
        col,
        "privileged context switching is controlled by an unsynchronized shared mode flag",
        out,
    );
}

/// CWE-421 — Race Condition During Access of Alternate Channel.
///
/// Freeze (C3 / #114): primary evidence is exact SI co-presence of a shared
/// transfer-token assignment plus an SSE event payload that embeds that token
/// (`transferToken` / `wireTransferCode` museums). No channel/goroutine data-flow
/// analysis — SSE format strings and field names are the entire proof.
///
/// Negatives: SI `sync.Mutex` / `transferMu` / `wireMu`.
/// Disposition: **fixture-only** (SSE + identifier museum; not structural).
pub(crate) fn detect_cwe_421(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (SI museum): shared token assign + SSE event embedding that token.
    // Not generalized alternate-channel analysis (no channel/goroutine dataflow).
    let shared_event_state = (facts.source_index.has("transferToken =")
        && facts
            .source_index
            .has("event: status\\ndata: \" + transferToken"))
        || (facts.source_index.has("wireTransferCode =")
            && facts
                .source_index
                .has("event: status\\ndata: %s\\n\\n\", wireTransferCode"));
    if !shared_event_state {
        return;
    }
    // Negative gate: mutex protecting the shared transfer state.
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

/// CWE-820 — Missing Synchronization.
///
/// Freeze (C3 / #114): primary evidence is exact SI map-counter museum
/// `visitCounts[key] = visitCounts[key] + 1` co-present with helper `TrackVisit`,
/// without `visitMu.Lock()` / `visitMu sync.Mutex`. Detecting general concurrent
/// map writes requires goroutine/handler lifecycle proof — out of C3 scope.
///
/// Disposition: **fixture-only** (helper + map-shape museum; not structural).
pub(crate) fn detect_cwe_820(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (SI museum): exact visit-counter map write + TrackVisit helper.
    // Not generalized concurrent-map-write detection (needs lifecycle proof).
    let unsynchronized_map_write = facts
        .source_index
        .has("visitCounts[key] = visitCounts[key] + 1")
        && facts.source_index.has("TrackVisit");
    if !unsynchronized_map_write {
        return;
    }
    // Negative gate: exclusive lock protecting the map update.
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

/// CWE-821 — Incorrect Synchronization.
///
/// Freeze (C3 / #114): local syntactic shape is "mutate shared map while holding
/// only a read lock". Call-facts become primary for the `.RLock` site; SI retains
/// the corpus map-write co-signal `tokenCache[key] = value` and the exclusive-lock
/// negative `cacheMu.Lock()`. No lock-set / critical-section analysis beyond
/// unit-local co-presence (not channel/goroutine ownership).
///
/// Disposition: **fixture-only** (RLock sink is production-shaped; emit still
/// gated on exact `tokenCache[key] = value` museum). Not structural under §1.3.
pub(crate) fn detect_cwe_821(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: read-lock token + corpus map-write shape.
    if !facts.source_index.has("RLock()") || !facts.source_index.has("tokenCache[key] = value") {
        return;
    }
    // Negative gate: exclusive lock used for the write path (safe fixtures).
    if facts.source_index.has("cacheMu.Lock()") {
        return;
    }

    // Primary signal: call facts — a `.RLock` call co-present with the SI map-write
    // museum above. Span at the read-lock call site (incorrect lock kind).
    let Some(rlock_call) = facts.call_facts.iter().find(|call| {
        let callee = call.callee.as_ref();
        callee == "RLock" || callee.ends_with(".RLock")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(rlock_call.start_byte);
    emit::push_finding(
        &META_CWE_821,
        file,
        line,
        col,
        "shared cache state is mutated while only a read lock is held",
        out,
    );
}
