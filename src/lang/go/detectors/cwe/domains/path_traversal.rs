use super::super::facts::GoUnitFacts;
use super::super::taint::detect_cwe_22_taint;
use crate::core::ParsedUnit;
use crate::rules::Finding;

pub(crate) fn detect_cwe_22(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    detect_cwe_22_taint(unit, facts, out);
}
