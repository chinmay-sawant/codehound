//! Detector trait — language-scoped analysis rule.

use crate::core::{LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, Rule};

/// Walks one parsed unit and appends findings.
pub trait Detector: Rule + Send + Sync {
    fn language(&self) -> LanguageId;
    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>);
}
