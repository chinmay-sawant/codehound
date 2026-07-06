//! Lightweight collector for named timing spans. Cloneable so per-worker
//! collectors can be merged back into a global collector after a parallel scan.
//!
//! Per-file and per-detector timing uses a global [`Mutex`]-protected collector
//! so that the `TimingCollector` does not need to be threaded through every
//! function signature and stored in every pipeline struct. App-level and
//! analyzer-level timing still uses locally-owned [`TimingCollector`] instances.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::summary::TimingSummary;

static GLOBAL: Mutex<Option<TimingCollector>> = Mutex::new(None);

/// Initialise the global collector for the scope of a scan chunk.
pub(crate) fn init_global(enabled: bool) {
    *GLOBAL
        .lock()
        .expect("global timing collector mutex poisoned") = Some(TimingCollector::new(enabled));
}

/// Start a span on the global collector. Returns the span index (0 when
/// disabled / uninitialised).
pub(crate) fn global_start(name: &'static str) -> usize {
    GLOBAL
        .lock()
        .expect("global timing collector mutex poisoned")
        .as_mut()
        .map(|c| c.start(name))
        .unwrap_or(0)
}

/// Stop a span started with [`global_start`].
pub(crate) fn global_stop(idx: usize) {
    if let Some(ref mut c) = *GLOBAL
        .lock()
        .expect("global timing collector mutex poisoned")
    {
        c.stop(idx);
    }
}

/// Drain the global collector into `target`. Resets the global to `None`.
pub(crate) fn drain_global(target: &mut TimingCollector) {
    if let Some(c) = GLOBAL
        .lock()
        .expect("global timing collector mutex poisoned")
        .take()
    {
        target.merge(&c);
    }
}

/// Run a closure with the global timing collector initialised and drain
/// the resulting [`TimingSummary`] afterwards. When `f` returns, the
/// global is reset to `None` regardless of panics.
///
/// This is the primary way for integration tests to exercise the
/// per-file / per-detector timing path.
#[cfg(test)]
#[allow(dead_code)]
pub fn with_timing<R>(f: impl FnOnce() -> R) -> (R, Option<TimingSummary>) {
    init_global(true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let summary = GLOBAL
        .lock()
        .expect("global timing collector mutex poisoned")
        .take()
        .map(|c| c.to_summary());
    // Reset even if the closure panicked so the global is clean for the
    // next test.
    *GLOBAL
        .lock()
        .expect("global timing collector mutex poisoned") = None;
    match result {
        Ok(val) => (val, summary),
        Err(e) => std::panic::resume_unwind(e),
    }
}

#[derive(Debug, Clone)]
pub struct TimingSpan {
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
