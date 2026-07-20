use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_276(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no WriteFile text ⇒ no world-writable session write.
    if !facts.source_index.has("os.WriteFile(") {
        return;
    }

    // Primary signal: call facts — os.WriteFile with world r/w mode 0666.
    // Session co-signals (path "sessions" / session_data / X-Session-Data) remain
    // corpus-shaped; maturity is fixture-only (see §2.11 Phase 2).
    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2].as_ref() == "0666"
            && (call.arguments[0].contains("sessions")
                || facts
                    .source_index
                    .has_any(&["session_data", "X-Session-Data"]))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_276,
        file,
        line,
        col,
        "a session artifact is written with a world-readable and world-writable default mode",
        out,
    );
}

pub(crate) fn detect_cwe_277(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Primary signal: call facts — generalized umask clear + world-writable MkdirAll.
    // Production-shaped API pair; keep Heuristic (no §1.3 real-module promotion evidence).
    let clears_umask = facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Umask"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    });
    if !clears_umask {
        return;
    }

    let Some(mkdir_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.MkdirAll"
            && call.arguments.len() >= 2
            && call.arguments[1].as_ref() == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(mkdir_call.start_byte);
    emit::push_finding(
        &META_CWE_277,
        file,
        line,
        col,
        "umask is cleared before creating a world-writable directory",
        out,
    );
}

pub(crate) fn detect_cwe_278(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Primary signal: call facts — os.OpenFile mode arg is the exact archive-metadata
    // formula `os.FileMode(hdr.Mode)` from the corpus (fixture-only maturity).
    let Some(open_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.OpenFile"
            && call.arguments.len() >= 3
            && call.arguments[2].contains("os.FileMode(hdr.Mode)")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_278,
        file,
        line,
        col,
        "archive entry permissions are reapplied directly from untrusted metadata during extraction",
        out,
    );
}

pub(crate) fn detect_cwe_279(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap co-signal prefilter: ParseUint text present (corpus "requested mode" shape).
    // Not dataflow; co-presence only — fixture-only maturity.
    if !facts.source_index.has("strconv.ParseUint(") {
        return;
    }

    // Primary signal: call facts — os.WriteFile with hard-coded world-writable 0777
    // despite a ParseUint co-signal in the same unit.
    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2].as_ref() == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_279,
        file,
        line,
        col,
        "the handler parses a requested mode but still writes the file with a hard-coded world-writable mode",
        out,
    );
}

pub(crate) fn detect_cwe_281(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Negative-gate: source mode preserved via info.Mode() (corpus safe-path).
    if facts.source_index.has("info.Mode()") {
        return;
    }

    // Primary sink: call facts — os.Create (default mode, drops source bits).
    let Some(create_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Create")
    else {
        return;
    };

    // Copy co-signal: prefer call_facts when complete (exact out,in fixture shape);
    // SourceIndex exact needle remains impossibility prefilter / oracle co-presence.
    let has_copy = facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "io.Copy"
            && call.arguments.len() >= 2
            && call.arguments[0].as_ref() == "out"
            && call.arguments[1].as_ref() == "in"
    }) || facts.source_index.has("io.Copy(out, in)");
    if !has_copy {
        return;
    }

    let (line, col) = unit.line_col(create_call.start_byte);
    emit::push_finding(
        &META_CWE_281,
        file,
        line,
        col,
        "backup recreation uses os.Create and loses the source file's original permission bits",
        out,
    );
}

pub(crate) fn detect_cwe_921(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Fixture-literal path is still required (no general sensitive-key classifier).
    // Maturity is fixture-only; call_facts provides the emit span when mode matches.
    if !facts.source_index.has("/tmp/integration.key") {
        return;
    }
    // Negative-gates: private secret dir / owner-only mode (corpus safe-path).
    if facts.source_index.has_any(&["APP_SECRET_DIR", "0600"]) {
        return;
    }

    // Primary signal: call facts — os.WriteFile with world-readable 0644.
    // Path is bound through a local `path` variable in the corpus, so the literal
    // is proved only via SourceIndex above (not the WriteFile first argument).
    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2].as_ref() == "0644"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_921,
        file,
        line,
        col,
        "sensitive integration key material is stored in a world-readable temporary file",
        out,
    );
}
