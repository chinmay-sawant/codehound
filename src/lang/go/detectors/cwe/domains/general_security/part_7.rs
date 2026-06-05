use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_1389(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let implicit_radix = (source.contains("ReserveSeats(") || source.contains("ReserveSeatsPure("))
        && source.contains("strconv.ParseInt(raw, 0, 64)");
    if !implicit_radix {
        return;
    }
    if source.contains("strconv.ParseInt(raw, 10, 64)") {
        return;
    }

    let start_byte = source.find("strconv.ParseInt(raw, 0, 64)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1389,
        file,
        line,
        col,
        "seat counts are parsed with base 0 and may accept alternate-radix prefixes unexpectedly",
        out,
    );
}
