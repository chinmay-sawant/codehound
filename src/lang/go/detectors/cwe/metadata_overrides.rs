const fn severity_for(id: u32) -> Severity {
    match id {
        15 => Severity::High,
        22 => Severity::High,
        41 => Severity::High,
        59 => Severity::High,
        76 => Severity::High,
        78 => Severity::High,
        79 => Severity::High,
        89 => Severity::High,
        90 => Severity::High,
        91 => Severity::High,
        93 => Severity::High,
        112 => Severity::High,
        140 => Severity::High,
        178 => Severity::High,
        179 => Severity::High,
        182 => Severity::High,
        184 => Severity::High,
        186 => Severity::High,
        201 => Severity::High,
        204 => Severity::High,
        208 => Severity::High,
        209 => Severity::High,
        212 => Severity::High,
        213 => Severity::High,
        214 => Severity::High,
        215 => Severity::High,
        250 => Severity::High,
        252 => Severity::High,
        256 => Severity::High,
        257 => Severity::High,
        260 => Severity::High,
        261 => Severity::High,
        262 => Severity::High,
        263 => Severity::High,
        266 => Severity::High,
        267 => Severity::High,
        268 => Severity::High,
        270 => Severity::High,
        272 => Severity::High,
        273 => Severity::High,
        274 => Severity::High,
        276 => Severity::High,
        277 => Severity::High,
        278 => Severity::High,
        279 => Severity::High,
        280 => Severity::High,
        281 => Severity::High,
        283 => Severity::High,
        289 => Severity::High,
        290 => Severity::High,
        294 => Severity::High,
        301 => Severity::High,
        303 => Severity::High,
        305 => Severity::High,
        306 => Severity::High,
        307 => Severity::High,
        308 => Severity::High,
        309 => Severity::High,
        312 => Severity::High,
        319 => Severity::High,
        322 => Severity::High,
        323 => Severity::High,
        324 => Severity::High,
        325 => Severity::High,
        328 => Severity::High,
        331 => Severity::High,
        334 => Severity::High,
        335 => Severity::High,
        338 => Severity::High,
        341 => Severity::High,
        342 => Severity::High,
        343 => Severity::High,
        344 => Severity::High,
        346 => Severity::High,
        347 => Severity::High,
        349 => Severity::High,
        353 => Severity::High,
        356 => Severity::High,
        358 => Severity::High,
        359 => Severity::High,
        360 => Severity::High,
        366 => Severity::High,
        367 => Severity::High,
        368 => Severity::High,
        378 => Severity::High,
        379 => Severity::High,
        385 => Severity::High,
        393 => Severity::High,
        403 => Severity::High,
        408 => Severity::High,
        412 => Severity::High,
        420 => Severity::High,
        421 => Severity::High,
        425 => Severity::High,
        426 => Severity::High,
        427 => Severity::High,
        434 => Severity::High,
        454 => Severity::High,
        455 => Severity::High,
        459 => Severity::High,
        472 => Severity::High,
        488 => Severity::High,
        494 => Severity::High,
        497 => Severity::High,
        501 => Severity::High,
        502 => Severity::High,
        515 => Severity::High,
        521 => Severity::High,
        523 => Severity::High,
        524 => Severity::High,
        538 => Severity::High,
        544 => Severity::High,
        547 => Severity::High,
        549 => Severity::High,
        551 => Severity::High,
        552 => Severity::High,
        565 => Severity::High,
        601 => Severity::High,
        603 => Severity::High,
        605 => Severity::High,
        611 => Severity::High,
        613 => Severity::High,
        618 => Severity::High,
        619 => Severity::High,
        620 => Severity::High,
        639 => Severity::High,
        640 => Severity::High,
        645 => Severity::High,
        648 => Severity::High,
        649 => Severity::High,
        653 => Severity::High,
        654 => Severity::High,
        656 => Severity::High,
        708 => Severity::High,
        756 => Severity::High,
        765 => Severity::High,
        778 => Severity::High,
        783 => Severity::High,
        798 => Severity::High,
        807 => Severity::High,
        820 => Severity::High,
        821 => Severity::High,
        826 => Severity::High,
        829 => Severity::High,
        836 => Severity::High,
        838 => Severity::High,
        841 => Severity::High,
        842 => Severity::High,
        909 => Severity::High,
        915 => Severity::High,
        916 => Severity::High,
        917 => Severity::High,
        918 => Severity::High,
        921 => Severity::High,
        924 => Severity::High,
        940 => Severity::High,
        941 => Severity::High,
        1051 => Severity::Medium,
        1052 => Severity::High,
        1067 => Severity::Medium,
        1125 => Severity::High,
        1173 => Severity::High,
        1204 => Severity::High,
        1220 => Severity::High,
        1230 => Severity::Medium,
        1236 => Severity::High,
        1240 => Severity::High,
        1265 => Severity::High,
        1286 => Severity::Medium,
        1289 => Severity::High,
        1322 => Severity::Medium,
        1327 => Severity::High,
        1333 => Severity::High,
        1389 => Severity::Medium,
        1392 => Severity::Critical,
        _ => Severity::High,
    }
}

const fn fix_for(id: u32) -> Option<&'static str> {
    match id {
        15 => Some("Use trusted configuration sources such as environment variables or fixed allow-lists."),
        22 => Some(
            "Normalize user input with filepath.Clean and enforce a trusted base-directory prefix check before file access.",
        ),
        41 => Some(
            "Resolve to a canonical path and verify it remains under the trusted root before file access.",
        ),
        59 => Some("Use os.Lstat and reject symlinks before opening the file."),
        76 => Some("Use context-appropriate escaping such as html.EscapeString for HTML output."),
        78 => Some(
            "Avoid sh -c for user input; pass fixed argv entries directly to exec.Command and validate the input.",
        ),
        79 => Some("Escape user-controlled HTML output with html.EscapeString or use a safe templating API."),
        89 => Some("Use parameterized queries or prepared statements instead of string formatting for SQL."),
        90 => Some("Escape LDAP metacharacters before formatting user-controlled values into filters."),
        91 => Some(
            "Use xml.Marshal or another structured XML encoder instead of formatting XML strings manually.",
        ),
        93 => Some("Strip CR and LF from user-controlled header components before setting HTTP headers."),
        112 => Some("Validate required XML fields and numeric constraints after unmarshaling untrusted XML."),
        140 => Some("Use encoding/csv to write CSV rows instead of joining fields with commas."),
        178 => Some(
            "Use strings.EqualFold or normalize both the allow-list and the incoming value consistently.",
        ),
        179 => Some("Decode the input first, then validate the final decoded form."),
        182 => Some(
            "Reject unexpected input instead of stripping characters into an allow-listed authorization token.",
        ),
        184 => Some(
            "Use an allow-list or strict parser for accepted filter syntax instead of a partial deny-list.",
        ),
        186 => Some(
            "Use a hostname regex that permits realistic labels and separators instead of only lowercase letters.",
        ),
        201 => Some("Project internal records into public response structs that omit secret-bearing fields."),
        204 => Some("Return a uniform response for authentication failures regardless of which check failed."),
        208 => Some(
            "Use subtle.ConstantTimeCompare or another constant-time comparison primitive for secret values.",
        ),
        209 => Some(
            "Log internal errors server-side and return a generic client message without embedded error details.",
        ),
        212 => Some(
            "Project records into an export type that omits or clears sensitive payment fields before marshaling.",
        ),
        213 => Some(
            "Return a policy-specific public profile DTO that omits compensation or other restricted fields.",
        ),
        214 => Some("Pass the secret through stdin or another non-visible channel instead of argv."),
        215 => Some("Remove secrets from debug logs and log only non-sensitive request metadata."),
        250 => Some(
            "Write sensitive runtime files with restrictive permissions such as 0o600 instead of 0o777.",
        ),
        252 => Some("Check the error returned by os.WriteFile and handle or propagate failures."),
        256 => Some(
            "Hash or otherwise transform passwords before persistence instead of storing the plaintext value.",
        ),
        257 => Some(
            "Use a one-way password hashing scheme instead of reversible encryption for stored passwords.",
        ),
        260 => Some(
            "Keep non-secret settings in config files and source secrets from the environment or a secret manager.",
        ),
        261 => Some(
            "Use a one-way hash or digest for password storage instead of reversible encodings like Base64.",
        ),
        262 => Some(
            "Track password change timestamps and reject or rotate credentials older than the allowed maximum age.",
        ),
        263 => Some(
            "Use a reasonably short password expiration window instead of multi-year validity periods.",
        ),
        266 => Some(
            "Assign roles server-side from a trusted default or policy instead of accepting them directly from the client.",
        ),
        267 => Some(
            "Restrict reviewer roles to safe review-specific actions and avoid granting direct destructive filesystem operations.",
        ),
        268 => Some(
            "Require an explicit high-trust role or dedicated export permission for sensitive bulk export paths.",
        ),
        270 => Some(
            "Save and restore the original execution context around privileged work instead of leaving the elevated principal in place.",
        ),
        272 => Some(
            "Drop the elevated uid as soon as the privileged operation completes instead of retaining it for the remainder of the handler.",
        ),
        273 => Some("Check the result of privilege-dropping syscalls and abort processing if the drop fails."),
        274 => Some(
            "Detect insufficient privilege errors such as EPERM and return a denial or failure response instead of reporting success.",
        ),
        276 => Some(
            "Write session and secret-bearing artifacts with restrictive owner-only permissions such as 0o600.",
        ),
        277 => Some("Use a restrictive umask and avoid clearing it to zero around filesystem creation."),
        278 => Some(
            "Clamp extracted file modes to a safe value instead of preserving untrusted archive permission bits.",
        ),
        279 => Some("Honor a validated bounded mode instead of forcing a broad hard-coded file permission."),
        280 => Some(
            "Treat access failures as denial conditions and do not continue into privileged deletion or mutation paths.",
        ),
        281 => Some(
            "Stat the source and recreate the destination with the source mode or another explicitly safe mode.",
        ),
        283 => Some(
            "Check the file's owner metadata against the authenticated caller before destructive file operations.",
        ),
        289 => Some(
            "Match against a canonical normalized principal identifier, including the full realm-qualified name.",
        ),
        290 => Some(
            "Derive identity from a validated server-side session or middleware context, not from caller-controlled headers.",
        ),
        294 => Some(
            "Require a nonce or one-time identifier and reject tokens whose nonce has already been consumed.",
        ),
        301 => Some(
            "Generate the proof from server-held secret material, such as an HMAC over the challenge, instead of echoing the challenge.",
        ),
        303 => Some("Decode the provided MAC and compare it with subtle.ConstantTimeCompare or hmac.Equal."),
        305 => Some(
            "Require authentication before any privileged branch and never use caller-controlled debug flags to bypass auth.",
        ),
        306 => Some(
            "Gate destructive functions with an authenticated operator check before performing the action.",
        ),
        307 => Some(
            "Track repeated failures and apply throttling, backoff, or lockout before processing more attempts.",
        ),
        308 => Some(
            "Require a validated second factor such as TOTP in addition to the password for high-value actions.",
        ),
        309 => Some(
            "Use a stronger primary authentication method such as WebAuthn or a trusted SSO assertion instead of password-only form login.",
        ),
        312 => Some(
            "Encrypt sensitive identifiers before database or disk persistence instead of storing cleartext values.",
        ),
        319 => Some("Terminate TLS before handling sensitive payment data and use HTTPS-only listeners."),
        322 => Some("Verify the peer certificate chain and hostname instead of setting InsecureSkipVerify."),
        323 => Some(
            "Generate a fresh random nonce for each AEAD encryption and store it alongside the ciphertext.",
        ),
        324 => Some("Reject expired keys before using them for signing or verification operations."),
        325 => Some(
            "Use an authenticated encryption mode such as AES-GCM instead of raw CTR encryption for sensitive data.",
        ),
        328 => Some("Use a stronger password hashing approach instead of MD5, such as a salted modern KDF."),
        331 => Some(
            "Generate recovery codes from cryptographic randomness with a large enough entropy budget.",
        ),
        334 => Some(
            "Generate tokens from a much larger cryptographic random space instead of small integer ranges.",
        ),
        335 => Some(
            "Use cryptographic randomness instead of seeding a PRNG from time for security-sensitive tokens or tickets.",
        ),
        338 => Some("Generate tokens from crypto/rand instead of math/rand for security-sensitive values."),
        341 => Some(
            "Generate device tokens from cryptographic randomness instead of predictable process and time state.",
        ),
        342 => Some(
            "Generate one-time codes from cryptographic randomness instead of incrementing previous values.",
        ),
        343 => Some(
            "Use fresh cryptographic randomness instead of deterministic state transitions for security-sensitive draws.",
        ),
        344 => Some(
            "Load signing secrets from managed secret material instead of embedding invariant constants in code.",
        ),
        346 => Some(
            "Validate Origin against a trusted allow-list before reflecting it and avoid credentialed reflection for untrusted origins.",
        ),
        347 => Some(
            "Verify the JWT signature with the expected public key before trusting any decoded claims.",
        ),
        349 => Some(
            "Use a typed validated trusted payload instead of mixing trusted indicators with raw untrusted profile data.",
        ),
        353 => Some("Verify an HMAC or other integrity check before accepting and storing external payloads."),
        356 => Some(
            "Require an explicit confirmation token or deliberate second confirmation step before destructive actions.",
        ),
        358 => Some(
            "Validate required JWT structure and expected algorithm fields before accepting bearer token contents.",
        ),
        359 => Some(
            "Authorize the requester and project data into a public-safe response shape before serialization.",
        ),
        360 => Some(
            "Use trusted connection metadata such as RemoteAddr instead of caller-controlled forwarded headers.",
        ),
        366 => Some("Use atomic or synchronized updates for shared mutable counters."),
        367 => Some(
            "Avoid separate check-then-use file flows; validate the path and use it directly in a single operation where possible.",
        ),
        368 => Some(
            "Guard privilege mode transitions with synchronization and avoid unsafely shared context flags.",
        ),
        378 => Some("Create temp files with restrictive permissions such as 0o600 and prefer CreateTemp."),
        379 => Some(
            "Create private temporary directories with restrictive permissions before staging temporary files.",
        ),
        385 => Some(
            "Use subtle.ConstantTimeCompare for secret comparisons instead of early-exit loops.",
        ),
        393 => Some(
            "Return an error status such as 500 or 404 when the lookup fails instead of replying with success.",
        ),
        403 => Some(
            "Close sensitive descriptors before launching child processes and avoid inheriting them into execed commands.",
        ),
        408 => Some("Authenticate the caller before performing expensive or amplifying work."),
        412 => Some(
            "Use a fixed server-controlled lock path rather than accepting the lock target from the client.",
        ),
        420 => Some(
            "Place alternate and debug channels behind the same authentication guard as the primary route.",
        ),
        421 => Some("Synchronize shared state used by alternate channels with the primary handler."),
        425 => Some("Mount restricted exports behind explicit admin authorization middleware."),
        426 => Some(
            "Load plugins only from fixed trusted directories and reject caller-controlled search paths.",
        ),
        427 => Some("Invoke helpers via absolute paths and do not mutate PATH from user input."),
        434 => Some("Allow-list upload extensions and store uploads under randomized safe names."),
        454 => Some("Load security policy flags from server configuration rather than client input."),
        455 => Some("Fail startup when required security material cannot be loaded."),
        459 => Some("Remove sensitive temporary files after use and close them deterministically."),
        472 => Some(
            "Resolve authorization roles server-side from the authenticated session or account state.",
        ),
        488 => Some(
            "Bind cart state to a validated server session instead of a client-controlled identifier.",
        ),
        494 => Some("Verify a pinned digest or signature before accepting downloaded executable content."),
        497 => Some(
            "Return only coarse health information from diagnostics and avoid exposing system internals.",
        ),
        501 => Some("Keep trusted decision state separate from untrusted request payloads."),
        502 => Some(
            "Use validated JSON or another constrained format for request payloads before privileged updates.",
        ),
        515 => Some(
            "Store per-tenant or per-request state in scoped storage instead of global cross-request flags.",
        ),
        521 => Some("Enforce a strong password policy before accepting or storing credentials."),
        523 => Some("Require TLS or redirect to HTTPS before processing login credentials."),
        524 => Some(
            "Keep tokens request-scoped or server-session-bound instead of storing them in shared process-wide caches.",
        ),
        538 => Some(
            "Write operational secrets only to restricted internal paths with tight file permissions.",
        ),
        544 => Some("Route database failures through one shared helper with consistent status handling."),
        547 => Some(
            "Load signing secrets from environment or secret storage instead of hard-coding them in source.",
        ),
        549 => Some("Never return password values in API responses or previews."),
        551 => Some("Canonicalize the path before applying authorization or routing checks."),
        552 => Some(
            "Restrict uploaded document permissions to owner-only access and sanitize the stored name.",
        ),
        565 => Some(
            "Validate cookie role claims against server-side session state before authorizing privileged actions.",
        ),
        601 => Some("Restrict redirects to validated same-site relative paths or an allow-list."),
        603 => Some(
            "Authorize state changes from server-side session identity instead of caller-supplied auth headers.",
        ),
        605 => Some(
            "Bind service listeners exclusively unless address reuse is explicitly required and justified.",
        ),
        611 => Some("Reject DOCTYPE and keep strict XML parsing enabled on bounded request bodies."),
        613 => Some("Use short-lived secure cookies and revoke server-side session state on logout."),
        618 => Some(
            "Expose only an allow-listed set of non-privileged methods instead of passing raw method names to a native helper.",
        ),
        619 => Some("Close database cursors with defer immediately after successful query creation."),
        620 => Some(
            "Require the current password or equivalent verified session proof before changing credentials.",
        ),
        639 => Some(
            "Scope caller-controlled record identifiers to the authenticated owner in the data query.",
        ),
        640 => Some("Require a single-use, time-limited reset token before changing the password."),
        645 => Some(
            "Allow several failures and use a temporary lockout window instead of locking after one attempt.",
        ),
        648 => Some(
            "Restrict ownership changes to application-controlled paths and fixed service identities.",
        ),
        649 => Some(
            "Authenticate encoded profile data with an HMAC or signature before trusting embedded roles.",
        ),
        653 => Some(
            "Use separate read-only and privileged stores or handles for public and admin paths.",
        ),
        654 => Some("Require authenticated session role checks in addition to any service credential."),
        656 => Some("Require authenticated admin authorization instead of relying on a hidden path."),
        708 => Some(
            "Restrict ownership assignments to controlled directories and fixed service uid or gid values.",
        ),
        756 => Some("Return a generic error response and keep internal details out of client-visible output."),
        765 => Some(
            "Use a single defer-based unlock or ensure each control path releases the lock exactly once.",
        ),
        778 => Some("Log authentication failures with actor and source metadata for auditability."),
        783 => Some("Use explicit parentheses to make authorization logic unambiguous."),
        798 => Some("Load credentials from environment or secret storage at runtime."),
        807 => Some(
            "Make security decisions from trusted connection metadata rather than spoofable request headers.",
        ),
        820 => Some("Protect shared mutable state with a mutex or another synchronization primitive."),
        821 => Some("Use an exclusive lock for writes to shared state."),
        826 => Some(
            "Keep shared resources alive until background work finishes or bind workers to scoped handles.",
        ),
        829 => Some("Load only allowlisted modules from a fixed trusted directory."),
        836 => Some(
            "Accept plaintext passwords over the authenticated channel and verify them against stored hashes server-side.",
        ),
        838 => Some("Ensure emitted bytes match the declared output encoding and content type."),
        841 => Some(
            "Require successful completion of the MFA or equivalent workflow step before password changes.",
        ),
        842 => Some("Assign a non-privileged default group to newly registered accounts."),
        909 => Some(
            "Guard global resource use with explicit initialization checks before dereferencing.",
        ),
        915 => Some(
            "Bind client input into an allowlisted DTO and update only explicitly permitted fields.",
        ),
        916 => Some(
            "Use a dedicated password hashing scheme with sufficient work factor such as bcrypt or equivalent.",
        ),
        917 => Some("Keep template structure fixed and pass user input only as data."),
        918 => Some("Parse the URL and enforce an explicit host allowlist before outbound fetches."),
        921 => Some("Store secrets only under private directories with restrictive file permissions."),
        924 => Some(
            "Verify a keyed integrity signature over the webhook body before applying its contents.",
        ),
        940 => Some(
            "Validate callback origin with a bound state token before accepting the authorization response.",
        ),
        941 => Some(
            "Derive notification destinations from authenticated or persisted account state rather than request parameters.",
        ),
        1051 => Some(
            "Load network destinations from deployment configuration rather than hard-coded literals.",
        ),
        1052 => Some(
            "Source database connection parameters from environment or secret-backed runtime configuration.",
        ),
        1067 => Some(
            "Use indexed prefix or exact-match predicates instead of leading-wildcard scans.",
        ),
        1125 => Some(
            "Expose only the minimum route surface publicly and gate administrative endpoints behind dedicated authorization.",
        ),
        1173 => Some(
            "Bind into a validated struct or perform explicit field validation before persistence.",
        ),
        1204 => Some(
            "Generate a unique random IV for each encryption operation and include it alongside the ciphertext.",
        ),
        1220 => Some(
            "Include the authenticated principal in the data access predicate, not just a coarse login check.",
        ),
        1230 => Some(
            "Strip sensitive metadata from redacted responses and return only the minimum transport headers needed.",
        ),
        1236 => Some(
            "Neutralize dangerous leading characters before writing untrusted data into CSV fields.",
        ),
        1240 => Some(
            "Use a standard authenticated encryption primitive such as AES-GCM instead of custom ciphers.",
        ),
        1265 => Some(
            "Keep the lock scope in one place or move the shared helper outside the locked section to avoid nested acquisition.",
        ),
        1286 => Some(
            "Use a strict decoder and validate structural fields before persisting configuration input.",
        ),
        1289 => Some(
            "Normalize the full path and enforce a canonical prefix constraint before serving the resource.",
        ),
        1322 => Some(
            "Schedule retries with timers or separate workers instead of blocking the event loop with sleep.",
        ),
        1327 => Some(
            "Bind administrative or local-only services to loopback or a tightly scoped interface.",
        ),
        1333 => Some(
            "Use linear-time validation patterns plus explicit length limits for attacker-controlled input.",
        ),
        1389 => Some("Use explicit base-10 parsing when the input contract is decimal-only."),
        1392 => Some(
            "Require bootstrap credentials from secret-backed configuration and avoid shipping default passwords.",
        ),
        _ => None,
    }
}
