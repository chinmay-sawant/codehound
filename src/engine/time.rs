//! ISO-8601 timestamp helpers backed by `jiff`.

/// Current UTC time as an ISO-8601 string (`2024-06-19T19:22:45Z`).
pub fn iso8601_utc_now() -> String {
    jiff::Timestamp::now().to_string()
}

/// Format a Unix-epoch seconds value as an ISO-8601 string.
pub fn iso8601_from_secs(secs: u64) -> String {
    jiff::Timestamp::from_second(secs as i64)
        .map(|t| t.to_string())
        .unwrap_or_default()
}
