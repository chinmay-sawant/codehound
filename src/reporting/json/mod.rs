//! JSON reporter.
//!
//! Two output modes:
//! - **NDJSON** (default): one finding per line, stream-friendly
//! - **Envelope** (`--json-envelope`): a single JSON object wrapping the
//!   run metadata + findings array

mod entry;
mod types;

pub use entry::{print, print_envelope};
pub use types::{DisplayCweRef, Envelope, FindingJson};
