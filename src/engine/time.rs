//! ISO-8601 timestamp helpers backed by `jiff`.

/// Current UTC time as an ISO-8601 string (`2024-06-19T19:22:45Z`).
pub fn iso8601_utc_now() -> String {
    jiff::Timestamp::now().to_string()
}
