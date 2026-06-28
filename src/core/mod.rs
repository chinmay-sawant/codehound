//! Language-agnostic contracts.

mod detector;
mod language;
mod scan;
mod unit;

pub use detector::Detector;
pub use language::{LanguageId, LanguagePlugin};
pub use scan::{FailPolicy, ScanContext};
pub use unit::ParsedUnit;
