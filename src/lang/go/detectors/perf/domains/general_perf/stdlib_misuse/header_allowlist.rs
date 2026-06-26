pub(crate) fn is_canonical_header(s: &str) -> bool {
    // A short, vetted list of common headers that are already
    // canonical. This is intentionally exact-case: `CanonicalHeaderKey`
    // would change inputs such as `ETag` to `Etag`, so those are not
    // redundant no-ops.
    const CANONICAL: &[&str] = &[
        "Accept",
        "Accept-Charset",
        "Accept-Encoding",
        "Accept-Language",
        "Authorization",
        "Cache-Control",
        "Content-Length",
        "Content-Type",
        "Cookie",
        "Date",
        "Etag",
        "Expect",
        "Expires",
        "From",
        "Host",
        "If-Match",
        "If-Modified-Since",
        "If-None-Match",
        "If-Range",
        "If-Unmodified-Since",
        "Keep-Alive",
        "Last-Modified",
        "Location",
        "Origin",
        "Pragma",
        "Range",
        "Referer",
        "Retry-After",
        "Server",
        "Set-Cookie",
        "Transfer-Encoding",
        "User-Agent",
        "Vary",
        "Via",
        "Warning",
        "Www-Authenticate",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Request-Id",
        "X-Csrf-Token",
    ];
    CANONICAL.contains(&s)
}

#[cfg(test)]
mod tests {
    use super::is_canonical_header;

    #[test]
    fn canonical_header_allowlist_matches_known_textproto_outputs() {
        for header in [
            "Content-Type",
            "Etag",
            "Www-Authenticate",
            "X-Csrf-Token",
            "X-Forwarded-For",
            "User-Agent",
        ] {
            assert!(is_canonical_header(header), "{header}");
        }
    }

    #[test]
    fn canonical_header_allowlist_rejects_uncurated_headers() {
        for header in ["ETag", "X-CSRF-Token", "x-request-id", "Custom-Header"] {
            assert!(!is_canonical_header(header), "{header}");
        }
    }
}
