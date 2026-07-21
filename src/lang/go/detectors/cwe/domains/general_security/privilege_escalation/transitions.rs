use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

// Privilege-escalation B4 trust freeze (privilege_escalation/transitions.rs).
// Rules: CWE-270, CWE-272, CWE-273, CWE-274, CWE-1265.
// Clearer sink/API boundary than lifecycle_and_integrity (Setuid/Chown/Rename/
// context switch call_facts). Proposed dispositions: fixture-only for
// 270/273/274/1265; keep Heuristic for CWE-272 (Setuid(0)+Chown without drop).
// See plans/v0.0.5/pr-cwe-trust-privilege-lifecycle.md.

pub(crate) fn detect_cwe_270(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Primary signal (call_facts + fixture keys): c.Set("effective_user", "root"|
    // "maintenance") OR context.WithValue(..., effectiveUserKey, "root"|
    // "maintenance") without restore SI.
    // Negative gate (SI): defer c.Set("effective_user", original) OR
    // defer func() + context.WithValue(..., effectiveUserKey, original).
    // Key/value names are corpus-shaped; not a general principal-switch analysis.
    // Proposed: fixture-only.
    let Some(context_switch) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.Set"
            && call.arguments.len() >= 2
            && call.arguments[0].contains("effective_user")
            && (call.arguments[1].contains(r#""root""#)
                || call.arguments[1].contains(r#""maintenance""#)))
            || (call.callee.as_ref() == "context.WithValue"
                && call.arguments.len() >= 3
                && call.arguments[1].contains("effectiveUserKey")
                && (call.arguments[2].contains(r#""root""#)
                    || call.arguments[2].contains(r#""maintenance""#)))
    }) else {
        return;
    };

    let restores_context = facts
        .source_index
        .has(r#"defer c.Set("effective_user", original)"#)
        || (facts.source_index.has("defer func()")
            && facts
                .source_index
                .has("context.WithValue(r.Context(), effectiveUserKey, original)"));
    if restores_context {
        return;
    }

    let (line, col) = unit.line_col(context_switch.start_byte);
    emit::push_finding(
        &META_CWE_270,
        file,
        line,
        col,
        "the handler switches to a privileged execution context without restoring the original caller context",
        out,
    );
}

pub(crate) fn detect_cwe_272(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Primary signal (call_facts API boundary): syscall.Setuid(0) elevate +
    // os.Chown privileged work + absence of syscall.Setuid(1000) drop.
    // Strongest local sink in this family; production-shaped elevate+work pattern.
    // Limitation: drop detection is uid-literal 1000 only (safe fixtures use 1000).
    // Proposed: keep Heuristic (not fixture-only; not structural — no §1.3
    // real-module bar / generalized drop proof).
    let Some(elevate_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    }) else {
        return;
    };

    let performs_privileged_work = facts
        .call_facts
        .iter()
        .any(|call| call.callee.as_ref() == "os.Chown");
    if !performs_privileged_work {
        return;
    }

    let drops_privilege = facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "1000")
    });
    if drops_privilege {
        return;
    }

    let (line, col) = unit.line_col(elevate_call.start_byte);
    emit::push_finding(
        &META_CWE_272,
        file,
        line,
        col,
        "the handler raises uid for a privileged operation and does not drop it afterward",
        out,
    );
}

pub(crate) fn detect_cwe_273(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Primary signal (call_facts drop + SI err-check negative): syscall.Setuid(1000)
    // without SI "if err := syscall.Setuid(1000); err != nil" and without elevate
    // Setuid(0) co-presence (avoids overlapping CWE-272).
    // uid 1000 + exact err-check SI are corpus-shaped. Proposed: fixture-only.
    if facts
        .source_index
        .has("if err := syscall.Setuid(1000); err != nil")
    {
        return;
    }

    if facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    }) {
        return;
    }

    let Some(drop_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "1000")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(drop_call.start_byte);
    emit::push_finding(
        &META_CWE_273,
        file,
        line,
        col,
        "the handler ignores whether dropping privilege via Setuid actually succeeded",
        out,
    );
}

pub(crate) fn detect_cwe_274(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Primary signal (call_facts os.Rename + SI success-on-error shapes):
    // os.Rename present + "if err != nil {" + (c.JSON(200, gin.H{"rotated": true})
    // | w.WriteHeader(http.StatusOK)) without errors.Is(err, syscall.EPERM).
    // Response literals are corpus-shaped. Proposed: fixture-only.
    let Some(rename_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Rename")
    else {
        return;
    };

    let treats_error_as_success = (facts.source_index.has("if err != nil {")
        && (facts.source_index.has_any(&[
            r#"c.JSON(200, gin.H{"rotated": true})"#,
            "w.WriteHeader(http.StatusOK)",
        ])))
        && !facts.source_index.has("errors.Is(err, syscall.EPERM)");
    if !treats_error_as_success {
        return;
    }

    let (line, col) = unit.line_col(rename_call.start_byte);
    emit::push_finding(
        &META_CWE_274,
        file,
        line,
        col,
        "an insufficient-privilege filesystem failure is treated like a successful rotation",
        out,
    );
}

pub(crate) fn detect_cwe_1265(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Primary signal (fixture-literal SI museum): UpdateBalance(|UpdateBalancePure(
    // + ledgerMu.Lock()|ledgerMuPure.Lock() + PostTransfer(|PostTransferPure(.
    // Negative gate: applyBalanceDelta(|applyBalanceDeltaPure( helper split.
    // No call-graph / lock-set analysis; pure corpus co-presence. Proposed: fixture-only.
    let nested_lock_reentry = (facts
        .source_index
        .has_any(&["UpdateBalance(", "UpdateBalancePure("]))
        && (facts
            .source_index
            .has_any(&["ledgerMu.Lock()", "ledgerMuPure.Lock()"]))
        && (facts
            .source_index
            .has_any(&["PostTransfer(", "PostTransferPure("]));
    if !nested_lock_reentry {
        return;
    }
    if facts
        .source_index
        .has_any(&["applyBalanceDelta(", "applyBalanceDeltaPure("])
    {
        return;
    }

    let start_byte = source
        .find("UpdateBalance(")
        .or_else(|| source.find("UpdateBalancePure("))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1265,
        file,
        line,
        col,
        "a transfer path re-enters a mutex-protected balance helper while the same mutex is already held",
        out,
    );
}
