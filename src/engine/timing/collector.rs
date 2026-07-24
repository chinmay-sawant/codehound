//! Lightweight collector for named timing spans. Cloneable so per-worker
//! collectors can be merged back into the scan-owned collector after a
//! parallel scan.
//!
//! Production scans use one collector per file and merge those collectors at
//! chunk boundaries. The legacy global helpers below are test-only coverage
//! for the old compatibility behavior.
//!
//! Detectors may also record nested spans against a **thread-local active
//! collector** installed by the scan worker (see [`with_active_collector`]).

use std::cell::RefCell;
use std::collections::HashMap;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::summary::TimingSummary;

thread_local! {
    /// Active per-file collector for nested detector/rule spans on this worker.
    static ACTIVE_COLLECTOR: RefCell<Option<TimingCollector>> = const { RefCell::new(None) };
}

/// Install `collector` as the thread-local active collector for the duration of `f`.
///
/// Used so multi-rule detectors can record per-rule spans without threading the
/// collector through the [`crate::core::Detector`] trait.
pub fn with_active_collector<R>(collector: &TimingCollector, f: impl FnOnce() -> R) -> R {
    ACTIVE_COLLECTOR.with(|slot| {
        let prev = slot.replace(Some(collector.clone()));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        slot.replace(prev);
        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    })
}

/// Time `f` under `name` on the active thread-local collector when present and
/// enabled; otherwise run `f` with no timing overhead.
pub fn measure_active<R>(name: &'static str, f: impl FnOnce() -> R) -> R {
    ACTIVE_COLLECTOR.with(|slot| {
        let Some(collector) = slot.borrow().as_ref().cloned() else {
            return f();
        };
        collector.measure(name, f)
    })
}

/// Whether the active thread-local collector is present and enabled.
pub fn active_enabled() -> bool {
    ACTIVE_COLLECTOR.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(TimingCollector::is_enabled)
    })
}

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

#[derive(Debug)]
pub(crate) struct TimingSpan {
    pub name: &'static str,
    pub start: Instant,
}

/// Collects named phase timings for a scan (or remains a no-op when disabled).
#[derive(Debug, Default)]
struct TimingState {
    active: HashMap<usize, TimingSpan>,
    aggregates: HashMap<&'static str, (Duration, usize)>,
    next_span_id: usize,
}

/// Collects named phase timings with bounded memory: completed spans are
/// aggregated by phase name immediately instead of retained per scanned file.
#[derive(Debug, Clone)]
pub struct TimingCollector {
    enabled: bool,
    state: Arc<Mutex<TimingState>>,
}

impl TimingCollector {
    /// Create a collector; when `enabled` is false, all timing calls are cheap no-ops.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            state: Arc::new(Mutex::new(TimingState::default())),
        }
    }

    pub(crate) const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Start a span and return its index. If disabled, returns 0 and does nothing.
    pub fn start(&self, name: &'static str) -> usize {
        if !self.enabled {
            return 0;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let id = state.next_span_id;
        state.next_span_id = state.next_span_id.wrapping_add(1);
        state.active.insert(
            id,
            TimingSpan {
                name,
                start: Instant::now(),
            },
        );
        id
    }

    /// Stop a span started with [`Self::start`]. If disabled, does nothing.
    pub fn stop(&self, index: usize) {
        if !self.enabled {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(span) = state.active.remove(&index) {
            let duration = span.start.elapsed();
            let entry = state
                .aggregates
                .entry(span.name)
                .or_insert((Duration::ZERO, 0));
            entry.0 += duration;
            entry.1 += 1;
        }
    }

    /// Time a closure and record its duration under the given name.
    pub fn measure<T>(&self, name: &'static str, f: impl FnOnce() -> T) -> T {
        if !self.enabled {
            return f();
        }
        let idx = self.start(name);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        self.stop(idx);
        match result {
            Ok(value) => value,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    /// Merge another collector's completed timing aggregates into this one.
    pub fn merge(&self, other: &Self) {
        if !self.enabled || !other.enabled {
            return;
        }
        if Arc::ptr_eq(&self.state, &other.state) {
            return;
        }
        let other_state = other
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (&name, &(duration, count)) in &other_state.aggregates {
            let entry = state.aggregates.entry(name).or_insert((Duration::ZERO, 0));
            entry.0 += duration;
            entry.1 += count;
        }
    }

    /// Merge an owned collector without cloning its recorded spans.
    pub fn merge_owned(&self, other: Self) {
        if !self.enabled || !other.enabled {
            return;
        }
        self.merge(&other);
    }

    /// Aggregate spans by name and compute total wall time.
    pub fn to_summary(&self) -> TimingSummary {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (total, phases) = super::aggregate::aggregate_phases(state.aggregates.clone());

        TimingSummary {
            total_wall_time: total,
            phases,
        }
    }
}

#[cfg(test)]
mod safety_tests {
    use super::*;

    #[test]
    fn nested_active_timing_is_safe_and_aggregated() {
        let collector = TimingCollector::new(true);
        with_active_collector(&collector, || {
            measure_active("outer", || {
                measure_active("inner", || {});
            });
        });

        let summary = collector.to_summary();
        assert_eq!(
            summary
                .phases
                .iter()
                .map(|phase| phase.count)
                .sum::<usize>(),
            2
        );
        assert!(summary.phases.iter().any(|phase| phase.name == "outer"));
        assert!(summary.phases.iter().any(|phase| phase.name == "inner"));
    }

    #[test]
    fn active_collector_is_restored_after_panic() {
        let collector = TimingCollector::new(true);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_active_collector(&collector, || panic!("expected"));
        }));
        assert!(result.is_err());
        assert!(!active_enabled());
    }

    #[test]
    fn panicking_measurement_cleans_up_the_active_span() {
        let collector = TimingCollector::new(true);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collector.measure("panic", || panic!("expected"));
        }));
        assert!(result.is_err());
        assert!(
            collector
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active
                .is_empty()
        );

        collector.measure("after_panic", || {});
        assert!(
            collector
                .to_summary()
                .phases
                .iter()
                .any(|phase| phase.name == "after_panic")
        );
    }
}
