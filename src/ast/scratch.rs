//! Per-thread scratch buffer for hot-path format-style string concatenation.

/// Detectors that build a needle with `format!` can use this to avoid
/// per-binding `String` allocations. Each Rayon worker has its own buffer.
pub fn scratch_contains(source: &str, prefix: &str, dynamic: &str, suffix: &str) -> bool {
    use std::cell::RefCell;
    use std::fmt::Write;

    thread_local! {
        static BUF: RefCell<String> = RefCell::new(String::with_capacity(128));
    }

    BUF.with_borrow_mut(|s| {
        s.clear();
        if write!(s, "{prefix}{dynamic}{suffix}").is_err() {
            return false;
        }
        source.contains(s.as_str())
    })
}
