use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(crate) fn push_at(
    unit: &ParsedUnit,
    out: &mut Vec<Finding>,
    meta: &crate::rules::RuleMetadata,
    byte: usize,
    message: &str,
) {
    let (line, col) = unit.line_col(byte);
    emit::push_finding(meta, unit.display_path.as_str(), line, col, message, out);
}

pub(crate) fn line_start_byte(source: &str, line_no: usize) -> usize {
    let mut byte = 0;
    for (idx, line) in source.lines().enumerate() {
        if idx == line_no {
            return byte;
        }
        byte += line.len() + 1;
    }
    byte
}
