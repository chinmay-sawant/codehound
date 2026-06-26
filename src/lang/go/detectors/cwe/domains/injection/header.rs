use super::super::super::common::*;
use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn detect_cwe_93(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    use crate::engine::scratch_contains;
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for binding in &facts.input_bindings {
        if binding.kind != InputKind::UserControlled {
            continue;
        }

        let strips_cr = scratch_contains(
            source,
            r#"strings.ReplaceAll("#,
            &binding.name,
            r#", "\r", "")"#,
        );
        let strips_lf = scratch_contains(
            source,
            r#"strings.ReplaceAll("#,
            &binding.name,
            r#", "\n", "")"#,
        );
        if strips_cr && strips_lf {
            continue;
        }

        let has_location_header_sink = facts.call_facts.iter().any(|call| {
            matches!(call.callee.as_ref(), "c.Header" | "w.Header().Set")
                && call.arguments.len() >= 2
                && call.arguments[0].as_ref() == r#""Location""#
                && argument_uses_identifier(&call.arguments[1], &binding.name)
        });
        if !has_location_header_sink {
            continue;
        }

        let start_byte = facts
            .call_facts
            .iter()
            .find(|call| {
                matches!(call.callee.as_ref(), "c.Header" | "w.Header().Set")
                    && call.arguments.len() >= 2
                    && call.arguments[0].as_ref() == r#""Location""#
                    && argument_uses_identifier(&call.arguments[1], &binding.name)
            })
            .map(|call| call.start_byte)
            .unwrap_or(0);

        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_CWE_93,
            file,
            line,
            col,
            "user-controlled input is concatenated into a Location header without CRLF stripping",
            out,
        );
    }
}
