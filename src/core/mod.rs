//! Language-agnostic contracts.

mod detector;
mod language;
mod profile;
mod scan;
mod unit;

pub use detector::Detector;
pub use language::{LanguageId, LanguagePlugin};
pub use profile::{ProfileApplyTarget, ScanProfile};
pub use scan::{FailPolicy, ScanContext};
pub use unit::ParsedUnit;
