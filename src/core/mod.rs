//! Language-agnostic contracts.

mod detector;
mod detector_kind;
mod language;
mod scan;
mod unit;

pub use detector::Detector;
pub use detector_kind::DetectorKind;
pub use language::{LanguageId, LanguagePlugin};
pub use scan::{FailPolicy, ScanContext};
pub use unit::ParsedUnit;
