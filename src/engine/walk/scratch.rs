//! Per-thread scratch buffer for hot-path `format!`-style string
//! concatenation used by detectors.

/// Per-thread scratch buffer for hot-path format-style string concatenation.
/// Detectors that build a needle string with `format!` (e.g. to check whether
/// the source contains a function call with a specific argument) can use
/// [`scratch_contains`] to avoid per-binding `String` allocations.
///
/// Each rayon worker thread has its own buffer; the buffer is reused
/// across all calls in that worker, so the steady-state cost is zero
/// allocations.
pub fn scratch_contains(source: &str, prefix: &str, dynamic: &str, suffix: &str) -> bool {
    use std::cell::RefCell;
    use std::fmt::Write;

    thread_local! {
        static BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
    }

    BUF.with_borrow_mut(|s| {
        s.clear();
        if write!(s, "{}{}{}", prefix, dynamic, suffix).is_err() {
            return false;
        }
        source.contains(s.as_str())
    })
}
