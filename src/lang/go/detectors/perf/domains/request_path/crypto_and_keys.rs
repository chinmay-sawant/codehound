use super::super::super::common::is_in_loop;
use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use super::is_request_handler;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// PERF-024: crypto hashers allocated inside a loop.
pub(crate) fn detect_perf_24(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let triggers = [
        "sha256.New",
        "sha1.New",
        "md5.New",
        "hmac.New",
        "blake2b.New256",
        "blake2s.New256",
    ];

    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_24,
            file,
            line,
            col,
            "crypto hasher is allocated inside a loop body",
            out,
        );
    }
}

/// PERF-025: rsa.GenerateKey / ecdsa.GenerateKey on a request path.
pub(crate) fn detect_perf_25(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let _source = unit.source.as_ref();

    let index_triggers = [
        "rsa.GenerateKey(",
        "rsa.GenerateMultiPrimeKey(",
        "ecdsa.GenerateKey(",
        "ed25519.GenerateKey(",
    ];
    let callee_triggers = [
        "rsa.GenerateKey",
        "rsa.GenerateMultiPrimeKey",
        "ecdsa.GenerateKey",
        "ed25519.GenerateKey",
    ];

    if !facts.source_index.has_any(&index_triggers) {
        return;
    }
    if facts.source_index.has("var (")
        && (facts.source_index.has("// gen once") || facts.source_index.has("sync.Once"))
    {
        return;
    }

    let on_request_path = is_request_handler(&facts.source_index);
    let in_loop = facts
        .calls
        .iter()
        .any(|c| is_in_loop(c) && callee_triggers.iter().any(|t| c.callee.as_ref() == *t));

    if !on_request_path && !in_loop {
        return;
    }

    for call in &facts.calls {
        if !callee_triggers.iter().any(|t| call.callee.as_ref() == *t) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_25,
            file,
            line,
            col,
            "asymmetric key pair is generated on a request path or in a loop",
            out,
        );
        return;
    }
}
