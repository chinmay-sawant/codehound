//! Lightweight collector for named timing spans. Cloneable so per-worker
//! collectors can be merged back into the scan-owned collector after a
//! parallel scan.
//!
//! Production scans use one collector per file and merge those collectors at
//! chunk boundaries. The legacy global helpers below are test-only coverage
//! for the old compatibility behavior.

#[cfg(test)]
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::summary::TimingSummary;

#[cfg(test)]
static GLOBAL: Mutex<Option<TimingCollector>> = Mutex::new(None);
#[cfg(test)]
static TIMING_SESSION: Mutex<()> = Mutex::new(());
#[cfg(test)]
static TIMING_ENABLED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn global_lock() -> std::sync::MutexGuard<'static, Option<TimingCollector>> {
    GLOBAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Initialise the global collector for a scan session.
#[cfg(test)]
pub(crate) fn init_global(enabled: bool) {
    TIMING_ENABLED.store(enabled, Ordering::Relaxed);
    *global_lock() = Some(TimingCollector::new(enabled));
}

/// Guard for a timed compatibility session.
///
/// Dropping the guard disables and clears the global collector, including when
/// scan execution returns early or unwinds through a panic boundary.
#[cfg(test)]
pub(crate) struct TimingSession {
    _guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TimingSession {
    fn drop(&mut self) {
        TIMING_ENABLED.store(false, Ordering::Relaxed);
        *global_lock() = None;
    }
}

/// Begin a timed scan session. Timed scans are serialized because the
/// per-file instrumentation still crosses Rayon worker threads through the
/// compatibility collector; normal scans do not touch or clear global timing.
#[cfg(test)]
pub(crate) fn begin_global(enabled: bool) -> Option<TimingSession> {
    if !enabled {
        return None;
    }
    let guard = TIMING_SESSION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    init_global(true);
    Some(TimingSession { _guard: guard })
}

#[cfg(test)]
pub(crate) fn reset_global() {
    TIMING_ENABLED.store(false, Ordering::Relaxed);
    *global_lock() = None;
}

/// Start a span on the global collector. Returns the span index (0 when
/// disabled / uninitialised).
#[cfg(test)]
pub(crate) fn global_start(name: &'static str) -> usize {
    if !TIMING_ENABLED.load(Ordering::Relaxed) {
        return 0;
    }
    global_lock().as_mut().map(|c| c.start(name)).unwrap_or(0)
}

/// Stop a span started with [`global_start`].
#[cfg(test)]
pub(crate) fn global_stop(idx: usize) {
    if !TIMING_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    if let Some(ref mut c) = *global_lock() {
        c.stop(idx);
    }
}

/// Drain the current chunk into `target` and start a fresh collector for the
/// next chunk in the same scan session.
#[cfg(test)]
pub(crate) fn drain_global(target: &mut TimingCollector) {
    let current = { global_lock().take() };
    if let Some(c) = current {
        let enabled = c.enabled;
        target.merge_owned(c);
        *global_lock() = Some(TimingCollector::new(enabled));
    }
}

/// Run a closure with the global timing collector initialised and drain
/// the resulting [`TimingSummary`] afterwards. When `f` returns, the
/// global is reset to `None` regardless of panics.
///
/// This is the primary way for integration tests to exercise the
/// per-file / per-detector timing path.
#[cfg(test)]
pub fn with_timing<R>(f: impl FnOnce() -> R) -> (R, Option<TimingSummary>) {
    let _guard = TIMING_SESSION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    init_global(true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    TIMING_ENABLED.store(false, Ordering::Relaxed);
    let summary = global_lock().take().map(|c| c.to_summary());
    // Reset even if the closure panicked so the global is clean for the
    // next test.
    *global_lock() = None;
    drop(_guard);
    match result {
        Ok(val) => (val, summary),
        Err(e) => std::panic::resume_unwind(e),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TimingSpan {
    pub name: &'static str,
    pub start: Instant,
    pub duration: Option<Duration>,
}

#[derive(Debug, Default, Clone)]
pub struct TimingCollector {
    spans: Vec<TimingSpan>,
    enabled: bool,
}

impl TimingCollector {
    pub fn new(enabled: bool) -> Self {
        Self {
            spans: Vec::new(),
            enabled,
        }
    }

    pub(crate) const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Start a span and return its index. If disabled, returns 0 and does nothing.
    pub fn start(&mut self, name: &'static str) -> usize {
        if !self.enabled {
            return 0;
        }
        let idx = self.spans.len();
        self.spans.push(TimingSpan {
            name,
            start: Instant::now(),
            duration: None,
        });
        idx
    }

    /// Stop a span started with [`Self::start`]. If disabled, does nothing.
    pub fn stop(&mut self, index: usize) {
        if !self.enabled {
            return;
        }
        if let Some(span) = self.spans.get_mut(index) {
            span.duration = Some(span.start.elapsed());
        }
    }

    /// Time a closure and record its duration under the given name.
    pub fn measure<T>(&mut self, name: &'static str, f: impl FnOnce() -> T) -> T {
        if !self.enabled {
            return f();
        }
        let idx = self.start(name);
        let result = f();
        self.stop(idx);
        result
    }

    /// Merge another collector into this one. Spans remain in chronological
    /// order within each phase name; aggregation happens in [`Self::to_summary`].
    pub fn merge(&mut self, other: &Self) {
        if !self.enabled || !other.enabled {
            return;
        }
        self.spans.extend(other.spans.iter().cloned());
    }

    /// Merge an owned collector without cloning its recorded spans.
    pub fn merge_owned(&mut self, mut other: Self) {
        if !self.enabled || !other.enabled {
            return;
        }
        self.spans.append(&mut other.spans);
    }

    /// Aggregate spans by name and compute total wall time.
    pub fn to_summary(&self) -> TimingSummary {
        let mut by_name: std::collections::HashMap<&'static str, (Duration, usize)> =
            std::collections::HashMap::new();
        let mut total = Duration::ZERO;

        for span in &self.spans {
            let Some(duration) = span.duration else {
                continue;
            };
            let entry = by_name.entry(span.name).or_insert((Duration::ZERO, 0));
            entry.0 += duration;
            entry.1 += 1;
            total += duration;
        }

        let (_, phases) = super::aggregate::aggregate_phases(by_name);

        TimingSummary {
            total_wall_time: total,
            phases,
        }
    }
}
