//! Baseline file support.

mod entry;
mod io;
mod store;

pub use entry::BaselineEntry;
pub use io::{BASELINE_FILE_NAME, discover_baseline};
pub use store::{BASELINE_VERSION, Baseline};
