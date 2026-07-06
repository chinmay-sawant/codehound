/// Conventional exit codes:
/// 0 — clean (no failing findings, no errors)
/// 1 — failing findings (per `FailPolicy`)
/// 2 — configuration error (unknown flag, invalid `codehound.toml`, ...)
/// 3 — internal / I-O / engine error (scan aborted before completion)
pub const EXIT_CLEAN: u8 = 0;
pub const EXIT_FAILING: u8 = 1;
pub const EXIT_CONFIG: u8 = 2;
pub const EXIT_INTERNAL: u8 = 3;
