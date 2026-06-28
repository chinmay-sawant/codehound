//! MIGRATED: All detectors formerly in this file have been moved to
//! domain-specific modules under `src/lang/go/detectors/perf/domains/`:
//!
//!   - `concurrency.rs`    — PERF-148, 167, 172, 173, 174, 175, 183, 193, 194
//!   - `memory_gc.rs`      — PERF-134, 138, 139, 150, 151, 169, 191
//!   - `string_bytes.rs`   — PERF-159, 178, 179, 186, 203
//!   - `stdlib_optimization.rs` — PERF-109, 142, 143, 144, 152, 153, 154, 155,
//!                                 160, 162, 164, 180, 184, 185, 187, 188, 189,
//!                                 196, 197, 199, 200, 201, 202, 205, 206, 207,
//!                                 210, 212
//!
//! The shared helpers `is_handler_shaped` and `file_has_handler` are in
//! `src/lang/go/detectors/perf/common.rs`.
//!
//! This file intentionally left blank.
