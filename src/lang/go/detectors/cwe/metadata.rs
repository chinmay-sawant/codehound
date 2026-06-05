use crate::rules::{RuleMetadata, Severity, emit};

pub(super) const GO_CWE_RULE_IDS: &[&str] = &[
    "CWE-15", "CWE-22", "CWE-41", "CWE-59", "CWE-76", "CWE-78", "CWE-79", "CWE-89", "CWE-90",
    "CWE-91", "CWE-93", "CWE-112", "CWE-140", "CWE-178", "CWE-179", "CWE-182", "CWE-184",
    "CWE-186", "CWE-201", "CWE-204", "CWE-208", "CWE-209", "CWE-212", "CWE-213", "CWE-214",
    "CWE-215", "CWE-250", "CWE-252", "CWE-256", "CWE-257", "CWE-260", "CWE-261", "CWE-262",
    "CWE-263", "CWE-266", "CWE-267", "CWE-268", "CWE-270", "CWE-272", "CWE-273", "CWE-274",
    "CWE-276", "CWE-277", "CWE-278", "CWE-279", "CWE-280", "CWE-281", "CWE-283", "CWE-289",
    "CWE-290", "CWE-294", "CWE-301", "CWE-303", "CWE-305", "CWE-306", "CWE-307", "CWE-308",
    "CWE-309", "CWE-312", "CWE-319", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-328",
    "CWE-331", "CWE-334", "CWE-335", "CWE-338", "CWE-341", "CWE-342", "CWE-343", "CWE-344",
    "CWE-346", "CWE-347", "CWE-349", "CWE-353", "CWE-356", "CWE-358", "CWE-359", "CWE-360",
    "CWE-366", "CWE-367", "CWE-368", "CWE-378", "CWE-379", "CWE-385", "CWE-393", "CWE-403",
    "CWE-408", "CWE-412", "CWE-420", "CWE-421", "CWE-425", "CWE-426", "CWE-427", "CWE-434",
    "CWE-454", "CWE-455", "CWE-459", "CWE-472", "CWE-488", "CWE-494", "CWE-497", "CWE-501",
    "CWE-502", "CWE-515", "CWE-521", "CWE-523", "CWE-524", "CWE-538", "CWE-544", "CWE-547",
    "CWE-549", "CWE-551", "CWE-552", "CWE-565", "CWE-601", "CWE-603", "CWE-605", "CWE-611",
    "CWE-613", "CWE-618", "CWE-619", "CWE-620", "CWE-639", "CWE-640", "CWE-645", "CWE-648",
    "CWE-649", "CWE-653", "CWE-654", "CWE-656", "CWE-708", "CWE-756", "CWE-765", "CWE-778",
    "CWE-783", "CWE-798", "CWE-807", "CWE-820", "CWE-821", "CWE-826", "CWE-829", "CWE-836",
    "CWE-838", "CWE-841", "CWE-842", "CWE-909", "CWE-915", "CWE-916", "CWE-917", "CWE-918",
    "CWE-921", "CWE-924", "CWE-940", "CWE-941", "CWE-1051", "CWE-1052", "CWE-1067", "CWE-1125",
    "CWE-1173", "CWE-1204", "CWE-1220", "CWE-1230", "CWE-1236", "CWE-1240", "CWE-1265", "CWE-1286",
    "CWE-1289", "CWE-1322", "CWE-1327", "CWE-1333", "CWE-1389", "CWE-1392",
];

pub(super) const META_CWE_15: RuleMetadata = emit::rule_meta(
    "CWE-15",
    "External control of configuration setting",
    "User-controlled request data is used as a runtime configuration value.",
    Severity::High,
    &[],
    Some("Use trusted configuration sources such as environment variables or fixed allow-lists."),
);

pub(super) const META_CWE_22: RuleMetadata = emit::rule_meta(
    "CWE-22",
    "Path traversal via user-controlled path segment",
    "User-controlled input is joined into a filesystem path without confining it to a trusted base directory.",
    Severity::High,
    &[],
    Some(
        "Normalize user input with filepath.Clean and enforce a trusted base-directory prefix check before file access.",
    ),
);

pub(super) const META_CWE_41: RuleMetadata = emit::rule_meta(
    "CWE-41",
    "Improper path equivalence resolution",
    "A partial path check rejects some traversal markers but still allows equivalent filesystem aliases to reach a file-read sink.",
    Severity::High,
    &[],
    Some(
        "Resolve to a canonical path and verify it remains under the trusted root before file access.",
    ),
);

pub(super) const META_CWE_59: RuleMetadata = emit::rule_meta(
    "CWE-59",
    "Improper link resolution before file access",
    "A user-controlled filesystem path is opened without rejecting symlink targets first.",
    Severity::High,
    &[],
    Some("Use os.Lstat and reject symlinks before opening the file."),
);

pub(super) const META_CWE_76: RuleMetadata = emit::rule_meta(
    "CWE-76",
    "Improper neutralization of equivalent special elements",
    "Manual stripping of literal HTML metacharacters does not safely neutralize equivalent encoded input in an HTML output context.",
    Severity::High,
    &[],
    Some("Use context-appropriate escaping such as html.EscapeString for HTML output."),
);

pub(super) const META_CWE_78: RuleMetadata = emit::rule_meta(
    "CWE-78",
    "OS command built from user-controlled shell input",
    "User-controlled input is interpolated into a shell command string executed through sh -c.",
    Severity::High,
    &[],
    Some(
        "Avoid sh -c for user input; pass fixed argv entries directly to exec.Command and validate the input.",
    ),
);

pub(super) const META_CWE_79: RuleMetadata = emit::rule_meta(
    "CWE-79",
    "Unescaped user input during HTML page generation",
    "User-controlled input is interpolated into HTML output without context-appropriate escaping.",
    Severity::High,
    &[],
    Some("Escape user-controlled HTML output with html.EscapeString or use a safe templating API."),
);

pub(super) const META_CWE_89: RuleMetadata = emit::rule_meta(
    "CWE-89",
    "SQL query built from user-controlled input",
    "User-controlled input is interpolated into an SQL query string before execution.",
    Severity::High,
    &[],
    Some("Use parameterized queries or prepared statements instead of string formatting for SQL."),
);

pub(super) const META_CWE_90: RuleMetadata = emit::rule_meta(
    "CWE-90",
    "LDAP filter built from user-controlled input",
    "User-controlled input is interpolated into an LDAP filter string without escaping LDAP metacharacters.",
    Severity::High,
    &[],
    Some("Escape LDAP metacharacters before formatting user-controlled values into filters."),
);

pub(super) const META_CWE_91: RuleMetadata = emit::rule_meta(
    "CWE-91",
    "XML document assembled from user-controlled fields",
    "User-controlled input is formatted into an XML document string instead of using typed XML marshaling.",
    Severity::High,
    &[],
    Some(
        "Use xml.Marshal or another structured XML encoder instead of formatting XML strings manually.",
    ),
);

pub(super) const META_CWE_93: RuleMetadata = emit::rule_meta(
    "CWE-93",
    "CRLF sequences copied into HTTP header values",
    "User-controlled input is concatenated into an HTTP header value without removing carriage return and line feed characters.",
    Severity::High,
    &[],
    Some("Strip CR and LF from user-controlled header components before setting HTTP headers."),
);

pub(super) const META_CWE_112: RuleMetadata = emit::rule_meta(
    "CWE-112",
    "Untrusted XML parsed without field validation",
    "Client-controlled XML is unmarshaled and used without validating required fields or value constraints.",
    Severity::High,
    &[],
    Some("Validate required XML fields and numeric constraints after unmarshaling untrusted XML."),
);

pub(super) const META_CWE_140: RuleMetadata = emit::rule_meta(
    "CWE-140",
    "CSV row built with naive delimiter concatenation",
    "User-controlled fields are joined into CSV output with literal delimiters instead of a CSV encoder.",
    Severity::High,
    &[],
    Some("Use encoding/csv to write CSV rows instead of joining fields with commas."),
);

pub(super) const META_CWE_178: RuleMetadata = emit::rule_meta(
    "CWE-178",
    "Inconsistent case handling in resource lookup",
    "User-controlled resource names are lowercased and then used in direct membership checks instead of a deliberate case-insensitive comparison.",
    Severity::High,
    &[],
    Some(
        "Use strings.EqualFold or normalize both the allow-list and the incoming value consistently.",
    ),
);

pub(super) const META_CWE_179: RuleMetadata = emit::rule_meta(
    "CWE-179",
    "Validation happens before URL decoding",
    "Encoded input is validated before URL decoding, so the validated form differs from the value later used.",
    Severity::High,
    &[],
    Some("Decode the input first, then validate the final decoded form."),
);

pub(super) const META_CWE_182: RuleMetadata = emit::rule_meta(
    "CWE-182",
    "Input is collapsed into a privileged value before authorization",
    "A normalization step removes non-alphanumeric content and collapses user input into an authorization-relevant value.",
    Severity::High,
    &[],
    Some(
        "Reject unexpected input instead of stripping characters into an allow-listed authorization token.",
    ),
);

pub(super) const META_CWE_184: RuleMetadata = emit::rule_meta(
    "CWE-184",
    "Incomplete list of disallowed inputs",
    "User-controlled input is normalized and checked against a small deny-list instead of being validated against an allow-list.",
    Severity::High,
    &[],
    Some(
        "Use an allow-list or strict parser for accepted filter syntax instead of a partial deny-list.",
    ),
);

pub(super) const META_CWE_186: RuleMetadata = emit::rule_meta(
    "CWE-186",
    "Overly restrictive regular expression used for host validation",
    "A simplistic host-validation regex rejects realistic hostnames and can lead to incorrect downstream behavior.",
    Severity::High,
    &[],
    Some(
        "Use a hostname regex that permits realistic labels and separators instead of only lowercase letters.",
    ),
);

pub(super) const META_CWE_201: RuleMetadata = emit::rule_meta(
    "CWE-201",
    "Sensitive record fields are serialized directly in a response",
    "An internal record containing secret-bearing fields is returned directly to the caller instead of being projected into a public response shape.",
    Severity::High,
    &[],
    Some("Project internal records into public response structs that omit secret-bearing fields."),
);

pub(super) const META_CWE_204: RuleMetadata = emit::rule_meta(
    "CWE-204",
    "Authentication failures reveal distinct account states",
    "Different error responses for missing accounts versus wrong credentials expose observable account state discrepancies.",
    Severity::High,
    &[],
    Some("Return a uniform response for authentication failures regardless of which check failed."),
);

pub(super) const META_CWE_208: RuleMetadata = emit::rule_meta(
    "CWE-208",
    "Secret comparison leaks mismatch timing",
    "A byte-by-byte comparison returns as soon as bytes differ instead of using a constant-time comparison.",
    Severity::High,
    &[],
    Some(
        "Use subtle.ConstantTimeCompare or another constant-time comparison primitive for secret values.",
    ),
);

pub(super) const META_CWE_209: RuleMetadata = emit::rule_meta(
    "CWE-209",
    "Client response includes database error details",
    "A database error is formatted directly into a client-facing response instead of being logged and replaced with a generic message.",
    Severity::High,
    &[],
    Some(
        "Log internal errors server-side and return a generic client message without embedded error details.",
    ),
);

pub(super) const META_CWE_212: RuleMetadata = emit::rule_meta(
    "CWE-212",
    "Sensitive payment fields are exported without removal",
    "A response or export marshals records that still contain sensitive payment fields such as card numbers or PANs.",
    Severity::High,
    &[],
    Some(
        "Project records into an export type that omits or clears sensitive payment fields before marshaling.",
    ),
);

pub(super) const META_CWE_213: RuleMetadata = emit::rule_meta(
    "CWE-213",
    "Public profile response includes policy-restricted compensation fields",
    "A public-facing profile response serializes internal compensation information instead of projecting to a policy-appropriate DTO.",
    Severity::High,
    &[],
    Some(
        "Return a policy-specific public profile DTO that omits compensation or other restricted fields.",
    ),
);

pub(super) const META_CWE_214: RuleMetadata = emit::rule_meta(
    "CWE-214",
    "Sensitive token passed on a process command line",
    "A secret token is supplied as an argv value to an external process where it may be visible to other local users or logs.",
    Severity::High,
    &[],
    Some("Pass the secret through stdin or another non-visible channel instead of argv."),
);

pub(super) const META_CWE_215: RuleMetadata = emit::rule_meta(
    "CWE-215",
    "Debug logging includes secret material",
    "A debug log statement includes a request-derived secret value that should not be written to logs.",
    Severity::High,
    &[],
    Some("Remove secrets from debug logs and log only non-sensitive request metadata."),
);

pub(super) const META_CWE_250: RuleMetadata = emit::rule_meta(
    "CWE-250",
    "Configuration file written with unnecessary broad permissions",
    "A file containing runtime state is written with world-accessible permissions instead of a restrictive owner-only mode.",
    Severity::High,
    &[],
    Some(
        "Write sensitive runtime files with restrictive permissions such as 0o600 instead of 0o777.",
    ),
);

pub(super) const META_CWE_252: RuleMetadata = emit::rule_meta(
    "CWE-252",
    "Critical file write return value is ignored",
    "A file write result is discarded instead of being checked and handled.",
    Severity::High,
    &[],
    Some("Check the error returned by os.WriteFile and handle or propagate failures."),
);

pub(super) const META_CWE_256: RuleMetadata = emit::rule_meta(
    "CWE-256",
    "Plaintext password is stored directly",
    "A user-provided password is persisted directly instead of being transformed into a hash or digest before storage.",
    Severity::High,
    &[],
    Some(
        "Hash or otherwise transform passwords before persistence instead of storing the plaintext value.",
    ),
);

pub(super) const META_CWE_257: RuleMetadata = emit::rule_meta(
    "CWE-257",
    "Password is stored in a recoverable encrypted format",
    "A password or login secret is encrypted with a reversible cipher and then stored, allowing later recovery.",
    Severity::High,
    &[],
    Some(
        "Use a one-way password hashing scheme instead of reversible encryption for stored passwords.",
    ),
);

pub(super) const META_CWE_260: RuleMetadata = emit::rule_meta(
    "CWE-260",
    "Secret is loaded from a configuration file body",
    "A password or secret-bearing field is read from a configuration file on disk instead of being sourced from a dedicated secret channel.",
    Severity::High,
    &[],
    Some(
        "Keep non-secret settings in config files and source secrets from the environment or a secret manager.",
    ),
);

pub(super) const META_CWE_261: RuleMetadata = emit::rule_meta(
    "CWE-261",
    "Password is stored using a reversible encoding",
    "A password is only Base64-encoded before storage, which preserves the underlying secret in a recoverable form.",
    Severity::High,
    &[],
    Some(
        "Use a one-way hash or digest for password storage instead of reversible encodings like Base64.",
    ),
);

pub(super) const META_CWE_262: RuleMetadata = emit::rule_meta(
    "CWE-262",
    "Credential age is never enforced",
    "Authentication logic loads credential metadata but does not check whether the password is older than a configured rotation window.",
    Severity::High,
    &[],
    Some(
        "Track password change timestamps and reject or rotate credentials older than the allowed maximum age.",
    ),
);

pub(super) const META_CWE_263: RuleMetadata = emit::rule_meta(
    "CWE-263",
    "Password expiration window is set unreasonably long",
    "The configured password maximum age is so long that password aging is effectively defeated.",
    Severity::High,
    &[],
    Some(
        "Use a reasonably short password expiration window instead of multi-year validity periods.",
    ),
);

pub(super) const META_CWE_266: RuleMetadata = emit::rule_meta(
    "CWE-266",
    "Client-controlled role is used for privilege assignment",
    "A role or privilege value is taken directly from client input when provisioning access instead of being assigned server-side.",
    Severity::High,
    &[],
    Some(
        "Assign roles server-side from a trusted default or policy instead of accepting them directly from the client.",
    ),
);

pub(super) const META_CWE_267: RuleMetadata = emit::rule_meta(
    "CWE-267",
    "Role is granted unsafe destructive capability",
    "A low-trust reviewer role is allowed to perform unsafe filesystem deletion actions.",
    Severity::High,
    &[],
    Some(
        "Restrict reviewer roles to safe review-specific actions and avoid granting direct destructive filesystem operations.",
    ),
);

pub(super) const META_CWE_268: RuleMetadata = emit::rule_meta(
    "CWE-268",
    "Privilege chaining exposes sensitive export behavior",
    "A sensitive export path is unlocked by combining weaker scopes instead of requiring a dedicated high-trust role or permission.",
    Severity::High,
    &[],
    Some(
        "Require an explicit high-trust role or dedicated export permission for sensitive bulk export paths.",
    ),
);

pub(super) const META_CWE_270: RuleMetadata = emit::rule_meta(
    "CWE-270",
    "Privileged execution context is switched without restoration",
    "The handler elevates the effective user or request context for privileged work but does not restore the original caller context afterward.",
    Severity::High,
    &[],
    Some(
        "Save and restore the original execution context around privileged work instead of leaving the elevated principal in place.",
    ),
);

pub(super) const META_CWE_272: RuleMetadata = emit::rule_meta(
    "CWE-272",
    "Elevated uid is retained longer than required",
    "The handler raises privilege for a privileged operation and keeps the elevated uid in place for the rest of the request instead of dropping it immediately.",
    Severity::High,
    &[],
    Some(
        "Drop the elevated uid as soon as the privileged operation completes instead of retaining it for the remainder of the handler.",
    ),
);

pub(super) const META_CWE_273: RuleMetadata = emit::rule_meta(
    "CWE-273",
    "Privilege drop result is ignored",
    "A privilege-dropping Setuid call is made, but its success is not checked before continuing request processing.",
    Severity::High,
    &[],
    Some("Check the result of privilege-dropping syscalls and abort processing if the drop fails."),
);

pub(super) const META_CWE_274: RuleMetadata = emit::rule_meta(
    "CWE-274",
    "Insufficient privilege errors are treated as success",
    "A privileged filesystem operation can fail due to insufficient privilege, but the handler still reports success instead of mapping the privilege error to a denial.",
    Severity::High,
    &[],
    Some(
        "Detect insufficient privilege errors such as EPERM and return a denial or failure response instead of reporting success.",
    ),
);

pub(super) const META_CWE_276: RuleMetadata = emit::rule_meta(
    "CWE-276",
    "Sensitive session file uses overly permissive default mode",
    "A session or secret-bearing artifact is written with world-readable or world-writable permissions instead of an owner-only mode.",
    Severity::High,
    &[],
    Some(
        "Write session and secret-bearing artifacts with restrictive owner-only permissions such as 0o600.",
    ),
);

pub(super) const META_CWE_277: RuleMetadata = emit::rule_meta(
    "CWE-277",
    "Cleared umask allows insecure inherited permissions",
    "The process clears umask before creating a directory, allowing overly permissive inherited modes to reach created content.",
    Severity::High,
    &[],
    Some("Use a restrictive umask and avoid clearing it to zero around filesystem creation."),
);

pub(super) const META_CWE_278: RuleMetadata = emit::rule_meta(
    "CWE-278",
    "Archive extraction preserves untrusted permission bits",
    "Archive entry permission bits are restored verbatim when creating files, allowing untrusted metadata to set insecure modes.",
    Severity::High,
    &[],
    Some(
        "Clamp extracted file modes to a safe value instead of preserving untrusted archive permission bits.",
    ),
);

pub(super) const META_CWE_279: RuleMetadata = emit::rule_meta(
    "CWE-279",
    "Execution assigns broader permissions than requested",
    "The handler parses a requested mode but still writes the file with a hard-coded world-writable mode.",
    Severity::High,
    &[],
    Some("Honor a validated bounded mode instead of forcing a broad hard-coded file permission."),
);

pub(super) const META_CWE_280: RuleMetadata = emit::rule_meta(
    "CWE-280",
    "Privilege failure falls through into a destructive path",
    "Failure to access a protected resource is treated as the branch that performs a destructive or privileged action instead of denying the request.",
    Severity::High,
    &[],
    Some(
        "Treat access failures as denial conditions and do not continue into privileged deletion or mutation paths.",
    ),
);

pub(super) const META_CWE_281: RuleMetadata = emit::rule_meta(
    "CWE-281",
    "Backup copy recreates file without preserving source permissions",
    "A file is copied with os.Create, which recreates it using process defaults instead of preserving the source file mode.",
    Severity::High,
    &[],
    Some(
        "Stat the source and recreate the destination with the source mode or another explicitly safe mode.",
    ),
);

pub(super) const META_CWE_283: RuleMetadata = emit::rule_meta(
    "CWE-283",
    "File deletion proceeds without verifying ownership",
    "A user-selected path is deleted without checking that the underlying file is owned by the authenticated caller.",
    Severity::High,
    &[],
    Some(
        "Check the file's owner metadata against the authenticated caller before destructive file operations.",
    ),
);

pub(super) const META_CWE_289: RuleMetadata = emit::rule_meta(
    "CWE-289",
    "Principal lookup ignores canonical realm-qualified identity",
    "Authentication looks up only the local username portion before the @ and can accept alternate-name aliases as the same principal.",
    Severity::High,
    &[],
    Some(
        "Match against a canonical normalized principal identifier, including the full realm-qualified name.",
    ),
);

pub(super) const META_CWE_290: RuleMetadata = emit::rule_meta(
    "CWE-290",
    "Client-controlled identity header is trusted as authentication",
    "The handler trusts a caller-supplied X-Remote-User header instead of deriving identity from validated server-side session state.",
    Severity::High,
    &[],
    Some(
        "Derive identity from a validated server-side session or middleware context, not from caller-controlled headers.",
    ),
);

pub(super) const META_CWE_294: RuleMetadata = emit::rule_meta(
    "CWE-294",
    "Authentication accepts replayable token without nonce tracking",
    "A login flow accepts a bearer or signed token without validating a one-time nonce or recording prior use, allowing capture and replay.",
    Severity::High,
    &[],
    Some(
        "Require a nonce or one-time identifier and reject tokens whose nonce has already been consumed.",
    ),
);

pub(super) const META_CWE_301: RuleMetadata = emit::rule_meta(
    "CWE-301",
    "Authentication proof reflects the client challenge",
    "The server returns the client-provided challenge directly as the authentication proof instead of transforming it with server-only key material.",
    Severity::High,
    &[],
    Some(
        "Generate the proof from server-held secret material, such as an HMAC over the challenge, instead of echoing the challenge.",
    ),
);

pub(super) const META_CWE_303: RuleMetadata = emit::rule_meta(
    "CWE-303",
    "MAC verification uses string equality instead of proper constant-time verification",
    "The authentication algorithm compares the computed MAC to user input with string equality instead of decoding and constant-time comparison.",
    Severity::High,
    &[],
    Some("Decode the provided MAC and compare it with subtle.ConstantTimeCompare or hmac.Equal."),
);

pub(super) const META_CWE_305: RuleMetadata = emit::rule_meta(
    "CWE-305",
    "Debug flag bypasses primary authentication",
    "A query-controlled debug branch reaches privileged functionality before the authenticated subject check runs.",
    Severity::High,
    &[],
    Some(
        "Require authentication before any privileged branch and never use caller-controlled debug flags to bypass auth.",
    ),
);

pub(super) const META_CWE_306: RuleMetadata = emit::rule_meta(
    "CWE-306",
    "Critical destructive function has no authentication gate",
    "A destructive operation is reachable without any authenticated operator or subject check.",
    Severity::High,
    &[],
    Some(
        "Gate destructive functions with an authenticated operator check before performing the action.",
    ),
);

pub(super) const META_CWE_307: RuleMetadata = emit::rule_meta(
    "CWE-307",
    "Authentication flow lacks attempt throttling or lockout",
    "The login path performs credential lookup and returns failures without tracking repeated attempts, delaying, or rate limiting.",
    Severity::High,
    &[],
    Some(
        "Track repeated failures and apply throttling, backoff, or lockout before processing more attempts.",
    ),
);

pub(super) const META_CWE_308: RuleMetadata = emit::rule_meta(
    "CWE-308",
    "High-value operation uses only a single factor",
    "A sensitive wire-transfer style action is authorized by password presence alone instead of requiring a validated second factor.",
    Severity::High,
    &[],
    Some(
        "Require a validated second factor such as TOTP in addition to the password for high-value actions.",
    ),
);

pub(super) const META_CWE_309: RuleMetadata = emit::rule_meta(
    "CWE-309",
    "Enterprise authentication relies on password form login only",
    "An enterprise login route treats username and password form fields as the primary authentication method instead of requiring a stronger assertion flow.",
    Severity::High,
    &[],
    Some(
        "Use a stronger primary authentication method such as WebAuthn or a trusted SSO assertion instead of password-only form login.",
    ),
);

pub(super) const META_CWE_312: RuleMetadata = emit::rule_meta(
    "CWE-312",
    "Sensitive identifier is stored in cleartext at rest",
    "A sensitive identifier such as an SSN is persisted directly in plaintext instead of being encrypted before storage.",
    Severity::High,
    &[],
    Some(
        "Encrypt sensitive identifiers before database or disk persistence instead of storing cleartext values.",
    ),
);

pub(super) const META_CWE_319: RuleMetadata = emit::rule_meta(
    "CWE-319",
    "Sensitive payment data is accepted over cleartext HTTP",
    "A payment endpoint handles PAN or CVV data while serving over plain HTTP instead of requiring TLS.",
    Severity::High,
    &[],
    Some("Terminate TLS before handling sensitive payment data and use HTTPS-only listeners."),
);

pub(super) const META_CWE_322: RuleMetadata = emit::rule_meta(
    "CWE-322",
    "TLS key exchange skips peer authentication",
    "A TLS relay connection disables certificate verification and therefore exchanges key material without authenticating the peer.",
    Severity::High,
    &[],
    Some("Verify the peer certificate chain and hostname instead of setting InsecureSkipVerify."),
);

pub(super) const META_CWE_323: RuleMetadata = emit::rule_meta(
    "CWE-323",
    "AEAD encryption reuses a fixed nonce",
    "A static nonce is reused with the same key for repeated AEAD encryption operations.",
    Severity::High,
    &[],
    Some(
        "Generate a fresh random nonce for each AEAD encryption and store it alongside the ciphertext.",
    ),
);

pub(super) const META_CWE_324: RuleMetadata = emit::rule_meta(
    "CWE-324",
    "Expired signing key is still used",
    "Cryptographic signing or verification proceeds without checking the key expiration time.",
    Severity::High,
    &[],
    Some("Reject expired keys before using them for signing or verification operations."),
);

pub(super) const META_CWE_325: RuleMetadata = emit::rule_meta(
    "CWE-325",
    "Encryption omits an integrity-protection step",
    "Sensitive data is encrypted with a stream mode like CTR but without an authentication tag or AEAD integrity step.",
    Severity::High,
    &[],
    Some(
        "Use an authenticated encryption mode such as AES-GCM instead of raw CTR encryption for sensitive data.",
    ),
);

pub(super) const META_CWE_328: RuleMetadata = emit::rule_meta(
    "CWE-328",
    "Weak hash algorithm is used for password storage",
    "A password digest is derived with MD5 instead of a stronger hashing construction.",
    Severity::High,
    &[],
    Some("Use a stronger password hashing approach instead of MD5, such as a salted modern KDF."),
);

pub(super) const META_CWE_331: RuleMetadata = emit::rule_meta(
    "CWE-331",
    "Recovery code uses insufficient entropy",
    "A security-sensitive recovery code is generated from a small decimal range using math/rand instead of cryptographic randomness.",
    Severity::High,
    &[],
    Some(
        "Generate recovery codes from cryptographic randomness with a large enough entropy budget.",
    ),
);

pub(super) const META_CWE_334: RuleMetadata = emit::rule_meta(
    "CWE-334",
    "Invite token comes from a very small random space",
    "A registration or invite token is generated from a very small 4096-value space and is easy to brute force.",
    Severity::High,
    &[],
    Some(
        "Generate tokens from a much larger cryptographic random space instead of small integer ranges.",
    ),
);

pub(super) const META_CWE_335: RuleMetadata = emit::rule_meta(
    "CWE-335",
    "PRNG is seeded from predictable wall-clock time",
    "A pseudo-random ticket is derived from a PRNG seeded with current time, making outputs predictable.",
    Severity::High,
    &[],
    Some(
        "Use cryptographic randomness instead of seeding a PRNG from time for security-sensitive tokens or tickets.",
    ),
);

pub(super) const META_CWE_338: RuleMetadata = emit::rule_meta(
    "CWE-338",
    "Session or access token uses a cryptographically weak PRNG",
    "A security token is generated with math/rand instead of cryptographic randomness.",
    Severity::High,
    &[],
    Some("Generate tokens from crypto/rand instead of math/rand for security-sensitive values."),
);

pub(super) const META_CWE_341: RuleMetadata = emit::rule_meta(
    "CWE-341",
    "Token is predictable from observable process and time state",
    "A device or pairing token is assembled from observable process id, timestamp, or caller-controlled values instead of cryptographic randomness.",
    Severity::High,
    &[],
    Some(
        "Generate device tokens from cryptographic randomness instead of predictable process and time state.",
    ),
);

pub(super) const META_CWE_342: RuleMetadata = emit::rule_meta(
    "CWE-342",
    "OTP is derived by incrementing the previous value",
    "A login code is produced by incrementing the prior OTP value, making the next exact value predictable from previous ones.",
    Severity::High,
    &[],
    Some(
        "Generate one-time codes from cryptographic randomness instead of incrementing previous values.",
    ),
);

pub(super) const META_CWE_343: RuleMetadata = emit::rule_meta(
    "CWE-343",
    "Pseudo-random output range is predictable from prior state transitions",
    "A raffle or prize value is computed from a deterministic linear recurrence over shared state instead of fresh random input.",
    Severity::High,
    &[],
    Some(
        "Use fresh cryptographic randomness instead of deterministic state transitions for security-sensitive draws.",
    ),
);

pub(super) const META_CWE_344: RuleMetadata = emit::rule_meta(
    "CWE-344",
    "Invariant hard-coded secret is used in a changing signing context",
    "An HMAC secret is hard-coded as a constant instead of being sourced from deploy-time secret material.",
    Severity::High,
    &[],
    Some(
        "Load signing secrets from managed secret material instead of embedding invariant constants in code.",
    ),
);

pub(super) const META_CWE_346: RuleMetadata = emit::rule_meta(
    "CWE-346",
    "Origin is reflected without validation",
    "A cross-origin response reflects the caller-supplied Origin value and enables credentials without validating the origin against a trusted allow-list.",
    Severity::High,
    &[],
    Some(
        "Validate Origin against a trusted allow-list before reflecting it and avoid credentialed reflection for untrusted origins.",
    ),
);

pub(super) const META_CWE_347: RuleMetadata = emit::rule_meta(
    "CWE-347",
    "JWT claims are accepted without signature verification",
    "A signed token payload is decoded and trusted without verifying the cryptographic signature first.",
    Severity::High,
    &[],
    Some(
        "Verify the JWT signature with the expected public key before trusting any decoded claims.",
    ),
);

pub(super) const META_CWE_349: RuleMetadata = emit::rule_meta(
    "CWE-349",
    "Trusted envelope carries extraneous untrusted profile data",
    "A trusted flag is accepted together with an untyped raw profile blob, and role-bearing fields from that raw blob are used directly.",
    Severity::High,
    &[],
    Some(
        "Use a typed validated trusted payload instead of mixing trusted indicators with raw untrusted profile data.",
    ),
);

pub(super) const META_CWE_353: RuleMetadata = emit::rule_meta(
    "CWE-353",
    "Inbound telemetry payload lacks integrity verification",
    "An external payload is ingested and persisted without verifying an integrity MAC or equivalent checksum.",
    Severity::High,
    &[],
    Some("Verify an HMAC or other integrity check before accepting and storing external payloads."),
);

pub(super) const META_CWE_356: RuleMetadata = emit::rule_meta(
    "CWE-356",
    "Destructive UI action lacks explicit confirmation token",
    "A destructive delete or purge action is executed without a separate explicit confirmation value from the caller.",
    Severity::High,
    &[],
    Some(
        "Require an explicit confirmation token or deliberate second confirmation step before destructive actions.",
    ),
);

pub(super) const META_CWE_358: RuleMetadata = emit::rule_meta(
    "CWE-358",
    "JWT structure standard check is incompletely implemented",
    "Bearer token claims are decoded without checking required structural or algorithm constraints from the token standard.",
    Severity::High,
    &[],
    Some(
        "Validate required JWT structure and expected algorithm fields before accepting bearer token contents.",
    ),
);

pub(super) const META_CWE_359: RuleMetadata = emit::rule_meta(
    "CWE-359",
    "Private personal information is exposed to unauthorized callers",
    "A profile response returns sensitive PII fields like SSN or phone without verifying the requester is authorized and without projecting to a public view.",
    Severity::High,
    &[],
    Some(
        "Authorize the requester and project data into a public-safe response shape before serialization.",
    ),
);

pub(super) const META_CWE_360: RuleMetadata = emit::rule_meta(
    "CWE-360",
    "Client-controlled forwarding header is trusted as system event data",
    "Security-sensitive IP recording trusts X-Forwarded-For instead of deriving the client address from the connection metadata.",
    Severity::High,
    &[],
    Some(
        "Use trusted connection metadata such as RemoteAddr instead of caller-controlled forwarded headers.",
    ),
);

pub(super) const META_CWE_366: RuleMetadata = emit::rule_meta(
    "CWE-366",
    "Shared credit state is updated with a non-atomic race-prone increment",
    "A shared mutable credit counter is incremented directly rather than with atomic or synchronized operations.",
    Severity::High,
    &[],
    Some("Use atomic or synchronized updates for shared mutable counters."),
);

pub(super) const META_CWE_367: RuleMetadata = emit::rule_meta(
    "CWE-367",
    "File is checked with Stat before later use",
    "A filesystem path is checked for existence or state and then used in a separate operation, creating a TOCTOU race window.",
    Severity::High,
    &[],
    Some(
        "Avoid separate check-then-use file flows; validate the path and use it directly in a single operation where possible.",
    ),
);

pub(super) const META_CWE_368: RuleMetadata = emit::rule_meta(
    "CWE-368",
    "Privilege mode switch relies on unsynchronized shared context flag",
    "A shared privileged-mode flag controls context switching without synchronization, creating race-prone privilege behavior.",
    Severity::High,
    &[],
    Some(
        "Guard privilege mode transitions with synchronization and avoid unsafely shared context flags.",
    ),
);

pub(super) const META_CWE_378: RuleMetadata = emit::rule_meta(
    "CWE-378",
    "Temporary file is created with insecure permissions",
    "A temporary export or upload file is created under TempDir with world-accessible permissions instead of a restrictive mode.",
    Severity::High,
    &[],
    Some("Create temp files with restrictive permissions such as 0o600 and prefer CreateTemp."),
);

pub(super) const META_CWE_379: RuleMetadata = emit::rule_meta(
    "CWE-379",
    "Temporary directory uses insecure permissions",
    "A temporary file is staged in a shared world-writable directory instead of a private restricted temporary directory.",
    Severity::High,
    &[],
    Some(
        "Create private temporary directories with restrictive permissions before staging temporary files.",
    ),
);

pub(super) const META_CWE_385: RuleMetadata = emit::rule_meta(
    "CWE-385",
    "Secret comparison leaks timing through early exit",
    "A secret is compared byte by byte with early return instead of using a constant-time comparison primitive.",
    Severity::High,
    &[],
    Some("Use subtle.ConstantTimeCompare for secret comparisons instead of early-exit loops."),
);

pub(super) const META_CWE_393: RuleMetadata = emit::rule_meta(
    "CWE-393",
    "Lookup failure returns a success status code",
    "An account lookup failure still returns HTTP 200 and a fallback payload instead of an error status.",
    Severity::High,
    &[],
    Some(
        "Return an error status such as 500 or 404 when the lookup fails instead of replying with success.",
    ),
);

pub(super) const META_CWE_403: RuleMetadata = emit::rule_meta(
    "CWE-403",
    "Sensitive file descriptor remains open across child process execution",
    "A sensitive file is opened before spawning a child process and is not closed before exec, exposing the descriptor to the child control sphere.",
    Severity::High,
    &[],
    Some(
        "Close sensitive descriptors before launching child processes and avoid inheriting them into execed commands.",
    ),
);

pub(super) const META_CWE_408: RuleMetadata = emit::rule_meta(
    "CWE-408",
    "Expensive export happens before authentication check",
    "The code performs a potentially amplifying query before checking whether the caller is authenticated.",
    Severity::High,
    &[],
    Some("Authenticate the caller before performing expensive or amplifying work."),
);

pub(super) const META_CWE_412: RuleMetadata = emit::rule_meta(
    "CWE-412",
    "Client controls the externally accessible lock path",
    "A lock file path is taken directly from the request, allowing external actors to point the lock mechanism at arbitrary locations.",
    Severity::High,
    &[],
    Some(
        "Use a fixed server-controlled lock path rather than accepting the lock target from the client.",
    ),
);

pub(super) const META_CWE_420: RuleMetadata = emit::rule_meta(
    "CWE-420",
    "Alternate debug channel bypasses the primary authenticated route",
    "A debug or alternate route exposes related functionality without the same authentication guard as the primary API route.",
    Severity::High,
    &[],
    Some(
        "Place alternate and debug channels behind the same authentication guard as the primary route.",
    ),
);

pub(super) const META_CWE_421: RuleMetadata = emit::rule_meta(
    "CWE-421",
    "Alternate event channel races shared transfer state",
    "An alternate SSE or event channel reads shared transfer state without synchronization while the primary handler writes it.",
    Severity::High,
    &[],
    Some("Synchronize shared state used by alternate channels with the primary handler."),
);

pub(super) const META_CWE_425: RuleMetadata = emit::rule_meta(
    "CWE-425",
    "Restricted admin export is reachable without authorization middleware",
    "An internal admin export endpoint is mounted without an explicit authorization guard.",
    Severity::High,
    &[],
    Some("Mount restricted exports behind explicit admin authorization middleware."),
);

pub(super) const META_CWE_426: RuleMetadata = emit::rule_meta(
    "CWE-426",
    "Plugin search path comes from the request",
    "Plugin or extension load paths are built from caller-controlled directories instead of fixed trusted roots.",
    Severity::High,
    &[],
    Some(
        "Load plugins only from fixed trusted directories and reject caller-controlled search paths.",
    ),
);

pub(super) const META_CWE_427: RuleMetadata = emit::rule_meta(
    "CWE-427",
    "PATH is prepended from user input before helper execution",
    "Caller-controlled directories are prepended to PATH before resolving a helper binary by name.",
    Severity::High,
    &[],
    Some("Invoke helpers via absolute paths and do not mutate PATH from user input."),
);

pub(super) const META_CWE_434: RuleMetadata = emit::rule_meta(
    "CWE-434",
    "Upload stores client filename without extension allow-list",
    "An uploaded file is stored and served using the client filename without restricting dangerous extensions or renaming safely.",
    Severity::High,
    &[],
    Some("Allow-list upload extensions and store uploads under randomized safe names."),
);

pub(super) const META_CWE_454: RuleMetadata = emit::rule_meta(
    "CWE-454",
    "Security policy bootstrap reads flag from untrusted request",
    "A security configuration flag is initialized from a client request instead of server-controlled configuration.",
    Severity::High,
    &[],
    Some("Load security policy flags from server configuration rather than client input."),
);

pub(super) const META_CWE_455: RuleMetadata = emit::rule_meta(
    "CWE-455",
    "Startup continues after security-critical initialization failure",
    "The process logs a failure to load required TLS or HSM material but continues starting anyway.",
    Severity::High,
    &[],
    Some("Fail startup when required security material cannot be loaded."),
);

pub(super) const META_CWE_459: RuleMetadata = emit::rule_meta(
    "CWE-459",
    "Sensitive temporary export file is never removed",
    "A temporary export file is created and served but not deleted afterward.",
    Severity::High,
    &[],
    Some("Remove sensitive temporary files after use and close them deterministically."),
);

pub(super) const META_CWE_472: RuleMetadata = emit::rule_meta(
    "CWE-472",
    "Hidden role field is trusted for authorization",
    "Authorization uses a role value submitted by the client rather than resolving the role server-side from the authenticated identity.",
    Severity::High,
    &[],
    Some(
        "Resolve authorization roles server-side from the authenticated session or account state.",
    ),
);

pub(super) const META_CWE_488: RuleMetadata = emit::rule_meta(
    "CWE-488",
    "Global cart state is keyed by client-controlled session id",
    "Cross-request cart state is stored in a global map keyed directly by a caller-supplied session identifier.",
    Severity::High,
    &[],
    Some(
        "Bind cart state to a validated server session instead of a client-controlled identifier.",
    ),
);

pub(super) const META_CWE_494: RuleMetadata = emit::rule_meta(
    "CWE-494",
    "Downloaded executable bundle lacks integrity verification",
    "A remotely downloaded worker bundle is written or executed without verifying a pinned digest first.",
    Severity::High,
    &[],
    Some("Verify a pinned digest or signature before accepting downloaded executable content."),
);

pub(super) const META_CWE_497: RuleMetadata = emit::rule_meta(
    "CWE-497",
    "Diagnostics expose host environment details",
    "A diagnostics endpoint returns hostnames, environment variables, or similar system internals to arbitrary callers.",
    Severity::High,
    &[],
    Some(
        "Return only coarse health information from diagnostics and avoid exposing system internals.",
    ),
);

pub(super) const META_CWE_501: RuleMetadata = emit::rule_meta(
    "CWE-501",
    "Trusted approval flag is merged into untrusted request struct",
    "Trusted decision state is stored in the same decoded request structure as untrusted client fields.",
    Severity::High,
    &[],
    Some("Keep trusted decision state separate from untrusted request payloads."),
);

pub(super) const META_CWE_502: RuleMetadata = emit::rule_meta(
    "CWE-502",
    "Untrusted gob payload is deserialized into a privileged action",
    "User-controlled gob data is decoded directly into an action struct that drives privileged state changes.",
    Severity::High,
    &[],
    Some(
        "Use validated JSON or another constrained format for request payloads before privileged updates.",
    ),
);

pub(super) const META_CWE_515: RuleMetadata = emit::rule_meta(
    "CWE-515",
    "Shared status flag creates a covert cross-request storage channel",
    "A global flag is written from one request and later read from another handler to disclose sensitive state.",
    Severity::High,
    &[],
    Some(
        "Store per-tenant or per-request state in scoped storage instead of global cross-request flags.",
    ),
);

pub(super) const META_CWE_521: RuleMetadata = emit::rule_meta(
    "CWE-521",
    "Password policy accepts trivially weak passwords",
    "Registration accepts effectively empty or one-character passwords before persistence.",
    Severity::High,
    &[],
    Some("Enforce a strong password policy before accepting or storing credentials."),
);

pub(super) const META_CWE_523: RuleMetadata = emit::rule_meta(
    "CWE-523",
    "Credentials are accepted over a cleartext listener",
    "Username and password login is served without requiring TLS before credentials are processed.",
    Severity::High,
    &[],
    Some("Require TLS or redirect to HTTPS before processing login credentials."),
);

pub(super) const META_CWE_524: RuleMetadata = emit::rule_meta(
    "CWE-524",
    "Process-wide cache stores raw session tokens",
    "Bearer or session tokens are cached in shared process memory keyed by user-controlled identifiers.",
    Severity::High,
    &[],
    Some(
        "Keep tokens request-scoped or server-session-bound instead of storing them in shared process-wide caches.",
    ),
);

pub(super) const META_CWE_538: RuleMetadata = emit::rule_meta(
    "CWE-538",
    "Sensitive DSN is exported to a public file path",
    "Database connection secrets are written to a world-readable path under a public static directory.",
    Severity::High,
    &[],
    Some(
        "Write operational secrets only to restricted internal paths with tight file permissions.",
    ),
);

pub(super) const META_CWE_544: RuleMetadata = emit::rule_meta(
    "CWE-544",
    "Database failures are handled inconsistently across handlers",
    "Different handlers react to similar database failures with ad-hoc panic and logging paths instead of one uniform error policy.",
    Severity::High,
    &[],
    Some("Route database failures through one shared helper with consistent status handling."),
);

pub(super) const META_CWE_547: RuleMetadata = emit::rule_meta(
    "CWE-547",
    "Signing secret is hard-coded in source",
    "JWT or MAC signing material is embedded as a source constant instead of loaded from managed runtime configuration.",
    Severity::High,
    &[],
    Some(
        "Load signing secrets from environment or secret storage instead of hard-coding them in source.",
    ),
);

pub(super) const META_CWE_549: RuleMetadata = emit::rule_meta(
    "CWE-549",
    "Password value is echoed back in an API response",
    "A signup or preview response includes the submitted password field in cleartext.",
    Severity::High,
    &[],
    Some("Never return password values in API responses or previews."),
);

pub(super) const META_CWE_551: RuleMetadata = emit::rule_meta(
    "CWE-551",
    "Authorization checks run on raw path before canonicalization",
    "A privileged path check is performed on the raw request path before percent-unescaping or normalization.",
    Severity::High,
    &[],
    Some("Canonicalize the path before applying authorization or routing checks."),
);

pub(super) const META_CWE_552: RuleMetadata = emit::rule_meta(
    "CWE-552",
    "Uploaded documents are chmodded world-readable",
    "Uploaded contract files are stored and then assigned world-readable or world-writable permissions.",
    Severity::High,
    &[],
    Some(
        "Restrict uploaded document permissions to owner-only access and sanitize the stored name.",
    ),
);

pub(super) const META_CWE_565: RuleMetadata = emit::rule_meta(
    "CWE-565",
    "Privileged delete trusts an unverified role cookie",
    "Authorization for a privileged delete action is derived directly from a client-controlled role cookie.",
    Severity::High,
    &[],
    Some(
        "Validate cookie role claims against server-side session state before authorizing privileged actions.",
    ),
);

pub(super) const META_CWE_601: RuleMetadata = emit::rule_meta(
    "CWE-601",
    "Redirect target is taken from an unvalidated caller parameter",
    "The application redirects to a caller-supplied next URL without enforcing a same-site policy.",
    Severity::High,
    &[],
    Some("Restrict redirects to validated same-site relative paths or an allow-list."),
);

pub(super) const META_CWE_603: RuleMetadata = emit::rule_meta(
    "CWE-603",
    "Server trusts a caller-supplied authenticated header",
    "Sensitive state changes rely on a client-provided authenticated marker instead of server-validated identity.",
    Severity::High,
    &[],
    Some(
        "Authorize state changes from server-side session identity instead of caller-supplied auth headers.",
    ),
);

pub(super) const META_CWE_605: RuleMetadata = emit::rule_meta(
    "CWE-605",
    "Listener enables SO_REUSEADDR on a service socket",
    "A service listener explicitly enables address reuse on the bound socket, weakening exclusive ownership on restart.",
    Severity::High,
    &[],
    Some(
        "Bind service listeners exclusively unless address reuse is explicitly required and justified.",
    ),
);

pub(super) const META_CWE_611: RuleMetadata = emit::rule_meta(
    "CWE-611",
    "Untrusted XML is parsed with strict mode disabled",
    "XML input is decoded with strict validation disabled and without defensive DOCTYPE rejection.",
    Severity::High,
    &[],
    Some("Reject DOCTYPE and keep strict XML parsing enabled on bounded request bodies."),
);

pub(super) const META_CWE_613: RuleMetadata = emit::rule_meta(
    "CWE-613",
    "Session cookie never expires and is not revoked",
    "Login issues a non-expiring session cookie and logout does not invalidate server-side session state.",
    Severity::High,
    &[],
    Some("Use short-lived secure cookies and revoke server-side session state on logout."),
);

pub(super) const META_CWE_618: RuleMetadata = emit::rule_meta(
    "CWE-618",
    "HTTP endpoint exposes a privileged native helper method",
    "A public endpoint forwards caller-controlled plugin method names and arguments to a privileged local helper binary.",
    Severity::High,
    &[],
    Some(
        "Expose only an allow-listed set of non-privileged methods instead of passing raw method names to a native helper.",
    ),
);

pub(super) const META_CWE_619: RuleMetadata = emit::rule_meta(
    "CWE-619",
    "Database cursor is left open on an early return path",
    "A sql.Rows cursor is created and can exit through an early return without being closed.",
    Severity::High,
    &[],
    Some("Close database cursors with defer immediately after successful query creation."),
);

pub(super) const META_CWE_620: RuleMetadata = emit::rule_meta(
    "CWE-620",
    "Password change does not verify the current password",
    "A password update replaces the stored credential without proving knowledge of the existing password.",
    Severity::High,
    &[],
    Some(
        "Require the current password or equivalent verified session proof before changing credentials.",
    ),
);

pub(super) const META_CWE_639: RuleMetadata = emit::rule_meta(
    "CWE-639",
    "Record lookup trusts a user-controlled key without owner scoping",
    "A caller-supplied record identifier is used directly without constraining the query to the authenticated owner.",
    Severity::High,
    &[],
    Some(
        "Scope caller-controlled record identifiers to the authenticated owner in the data query.",
    ),
);

pub(super) const META_CWE_640: RuleMetadata = emit::rule_meta(
    "CWE-640",
    "Forgot-password flow resets credentials from email alone",
    "The recovery flow changes a password using only the submitted email address without a time-limited reset token.",
    Severity::High,
    &[],
    Some("Require a single-use, time-limited reset token before changing the password."),
);

pub(super) const META_CWE_645: RuleMetadata = emit::rule_meta(
    "CWE-645",
    "Account lockout triggers after a single failed login",
    "The lockout policy permanently or immediately blocks the account after one failed attempt.",
    Severity::High,
    &[],
    Some(
        "Allow several failures and use a temporary lockout window instead of locking after one attempt.",
    ),
);

pub(super) const META_CWE_648: RuleMetadata = emit::rule_meta(
    "CWE-648",
    "Web handler exposes privileged chown with caller-supplied uid",
    "A request handler passes caller-controlled path and uid values into a privileged ownership-changing API.",
    Severity::High,
    &[],
    Some(
        "Restrict ownership changes to application-controlled paths and fixed service identities.",
    ),
);

pub(super) const META_CWE_649: RuleMetadata = emit::rule_meta(
    "CWE-649",
    "Base64-obfuscated role cookie is trusted without integrity checking",
    "The application decodes an obfuscated profile cookie and trusts the embedded role without verifying integrity.",
    Severity::High,
    &[],
    Some(
        "Authenticate encoded profile data with an HMAC or signature before trusting embedded roles.",
    ),
);

pub(super) const META_CWE_653: RuleMetadata = emit::rule_meta(
    "CWE-653",
    "Public and admin paths share the same privileged data store",
    "Unprivileged and privileged operations use the same privileged backing store instead of separate compartments.",
    Severity::High,
    &[],
    Some("Use separate read-only and privileged stores or handles for public and admin paths."),
);

pub(super) const META_CWE_654: RuleMetadata = emit::rule_meta(
    "CWE-654",
    "Admin access relies only on a static API key header",
    "A privileged export is authorized solely by a single static header value rather than layered identity checks.",
    Severity::High,
    &[],
    Some("Require authenticated session role checks in addition to any service credential."),
);

pub(super) const META_CWE_656: RuleMetadata = emit::rule_meta(
    "CWE-656",
    "Admin functionality is protected only by a secret URL path",
    "Sensitive configuration access relies on obscurity of the route path instead of real authorization.",
    Severity::High,
    &[],
    Some("Require authenticated admin authorization instead of relying on a hidden path."),
);

pub(super) const META_CWE_708: RuleMetadata = emit::rule_meta(
    "CWE-708",
    "Caller chooses file ownership assignment target and uid",
    "A file ownership operation uses caller-controlled destination and owner identifiers rather than a fixed service identity.",
    Severity::High,
    &[],
    Some(
        "Restrict ownership assignments to controlled directories and fixed service uid or gid values.",
    ),
);

pub(super) const META_CWE_756: RuleMetadata = emit::rule_meta(
    "CWE-756",
    "Raw database error text is returned to the client",
    "An internal database error is sent directly to the client instead of a generic error response.",
    Severity::High,
    &[],
    Some("Return a generic error response and keep internal details out of client-visible output."),
);

pub(super) const META_CWE_765: RuleMetadata = emit::rule_meta(
    "CWE-765",
    "Mutex is unlocked twice on an error path",
    "The same critical-section lock is explicitly released more than once on a validation failure path.",
    Severity::High,
    &[],
    Some(
        "Use a single defer-based unlock or ensure each control path releases the lock exactly once.",
    ),
);

pub(super) const META_CWE_778: RuleMetadata = emit::rule_meta(
    "CWE-778",
    "Authentication failures are not logged",
    "Security-relevant login failures return unauthorized responses without recording an audit event.",
    Severity::High,
    &[],
    Some("Log authentication failures with actor and source metadata for auditability."),
);

pub(super) const META_CWE_783: RuleMetadata = emit::rule_meta(
    "CWE-783",
    "Authorization condition relies on ambiguous operator precedence",
    "A mixed boolean expression depends on && and || precedence and grants or denies access unexpectedly.",
    Severity::High,
    &[],
    Some("Use explicit parentheses to make authorization logic unambiguous."),
);

pub(super) const META_CWE_798: RuleMetadata = emit::rule_meta(
    "CWE-798",
    "Database credentials are hard-coded in source",
    "A database DSN with embedded credentials is stored directly in the source code.",
    Severity::High,
    &[],
    Some("Load credentials from environment or secret storage at runtime."),
);

pub(super) const META_CWE_820: RuleMetadata = emit::rule_meta(
    "CWE-820",
    "Shared map is updated without synchronization",
    "Concurrent handlers mutate a shared map without any lock protection.",
    Severity::High,
    &[],
    Some("Protect shared mutable state with a mutex or another synchronization primitive."),
);

pub(super) const META_CWE_821: RuleMetadata = emit::rule_meta(
    "CWE-821",
    "Shared cache is mutated under a read lock",
    "A write to shared state occurs while only a read lock is held.",
    Severity::High,
    &[],
    Some("Use an exclusive lock for writes to shared state."),
);

pub(super) const META_CWE_826: RuleMetadata = emit::rule_meta(
    "CWE-826",
    "Shared database handle is closed before background work completes",
    "A background task still depends on a database handle after the shared handle has already been closed.",
    Severity::High,
    &[],
    Some(
        "Keep shared resources alive until background work finishes or bind workers to scoped handles.",
    ),
);

pub(super) const META_CWE_829: RuleMetadata = emit::rule_meta(
    "CWE-829",
    "Plugin is loaded from a caller-controlled filesystem path",
    "A shared object is loaded from a user-supplied path without an allowlist or fixed module root.",
    Severity::High,
    &[],
    Some("Load only allowlisted modules from a fixed trusted directory."),
);

pub(super) const META_CWE_836: RuleMetadata = emit::rule_meta(
    "CWE-836",
    "Authentication trusts a client-supplied password hash",
    "The caller submits a password hash that is compared directly to stored credential material.",
    Severity::High,
    &[],
    Some(
        "Accept plaintext passwords over the authenticated channel and verify them against stored hashes server-side.",
    ),
);

pub(super) const META_CWE_838: RuleMetadata = emit::rule_meta(
    "CWE-838",
    "Response emits invalid bytes for the declared output encoding",
    "The handler declares UTF-8 JSON but writes invalid byte sequences before the payload.",
    Severity::High,
    &[],
    Some("Ensure emitted bytes match the declared output encoding and content type."),
);

pub(super) const META_CWE_841: RuleMetadata = emit::rule_meta(
    "CWE-841",
    "Password reset workflow skips the MFA completion step",
    "A multi-step recovery or reset flow changes credentials without enforcing the required MFA gate.",
    Severity::High,
    &[],
    Some(
        "Require successful completion of the MFA or equivalent workflow step before password changes.",
    ),
);

pub(super) const META_CWE_842: RuleMetadata = emit::rule_meta(
    "CWE-842",
    "New users are placed into an administrator group by default",
    "Registration assigns new accounts to a privileged group instead of the standard member role.",
    Severity::High,
    &[],
    Some("Assign a non-privileged default group to newly registered accounts."),
);

pub(super) const META_CWE_909: RuleMetadata = emit::rule_meta(
    "CWE-909",
    "Global database handle is used before initialization is checked",
    "A global resource handle is dereferenced without verifying that startup initialization has occurred.",
    Severity::High,
    &[],
    Some("Guard global resource use with explicit initialization checks before dereferencing."),
);

pub(super) const META_CWE_915: RuleMetadata = emit::rule_meta(
    "CWE-915",
    "User-controlled map updates privileged object attributes",
    "A dynamic attribute map from the client is applied directly to a persistent object, including privileged fields.",
    Severity::High,
    &[],
    Some("Bind client input into an allowlisted DTO and update only explicitly permitted fields."),
);

pub(super) const META_CWE_916: RuleMetadata = emit::rule_meta(
    "CWE-916",
    "Password storage uses an insufficiently expensive hash",
    "Password registration uses a fast hash such as MD5 rather than a work-factor-based password hashing scheme.",
    Severity::High,
    &[],
    Some(
        "Use a dedicated password hashing scheme with sufficient work factor such as bcrypt or equivalent.",
    ),
);

pub(super) const META_CWE_917: RuleMetadata = emit::rule_meta(
    "CWE-917",
    "User input is concatenated into template source",
    "A template expression is constructed by concatenating caller-controlled data into the template body itself.",
    Severity::High,
    &[],
    Some("Keep template structure fixed and pass user input only as data."),
);

pub(super) const META_CWE_918: RuleMetadata = emit::rule_meta(
    "CWE-918",
    "Outbound fetch uses a caller-controlled URL without host allowlisting",
    "The server issues outbound requests to arbitrary client-supplied URLs without validating scheme or host.",
    Severity::High,
    &[],
    Some("Parse the URL and enforce an explicit host allowlist before outbound fetches."),
);

pub(super) const META_CWE_921: RuleMetadata = emit::rule_meta(
    "CWE-921",
    "Secret material is written to a world-readable file path",
    "Sensitive integration keys are stored in a broadly accessible path with permissive file mode.",
    Severity::High,
    &[],
    Some("Store secrets only under private directories with restrictive file permissions."),
);

pub(super) const META_CWE_924: RuleMetadata = emit::rule_meta(
    "CWE-924",
    "Inbound webhook payload is trusted without integrity verification",
    "A payment webhook body is applied directly without validating an HMAC or equivalent integrity proof.",
    Severity::High,
    &[],
    Some("Verify a keyed integrity signature over the webhook body before applying its contents."),
);

pub(super) const META_CWE_940: RuleMetadata = emit::rule_meta(
    "CWE-940",
    "OAuth callback accepts any source without state verification",
    "An inbound callback consumes authorization data without validating the origin through a state binding.",
    Severity::High,
    &[],
    Some(
        "Validate callback origin with a bound state token before accepting the authorization response.",
    ),
);

pub(super) const META_CWE_941: RuleMetadata = emit::rule_meta(
    "CWE-941",
    "Outbound reset notification is sent to a caller-controlled destination",
    "A password-reset or account message is delivered to an arbitrary user-supplied email destination.",
    Severity::High,
    &[],
    Some(
        "Derive notification destinations from authenticated or persisted account state rather than request parameters.",
    ),
);

pub(super) const META_CWE_1051: RuleMetadata = emit::rule_meta(
    "CWE-1051",
    "Network client is initialized with a hard-coded endpoint",
    "An outbound HTTP client always uses a fixed internal billing host instead of runtime configuration.",
    Severity::Warning,
    &[],
    Some(
        "Load network destinations from deployment configuration rather than hard-coded literals.",
    ),
);

pub(super) const META_CWE_1052: RuleMetadata = emit::rule_meta(
    "CWE-1052",
    "Database initialization embeds a full DSN literal",
    "A database connection string hard-codes host and credentials directly in the source.",
    Severity::High,
    &[],
    Some(
        "Source database connection parameters from environment or secret-backed runtime configuration.",
    ),
);

pub(super) const META_CWE_1067: RuleMetadata = emit::rule_meta(
    "CWE-1067",
    "Search query forces sequential scans with a leading wildcard pattern",
    "A caller-controlled LIKE query is constructed as '%term%', defeating indexed prefix access.",
    Severity::Warning,
    &[],
    Some("Use indexed prefix or exact-match predicates instead of leading-wildcard scans."),
);

pub(super) const META_CWE_1173: RuleMetadata = emit::rule_meta(
    "CWE-1173",
    "Validation framework is bypassed in favor of raw map decoding",
    "Request data is decoded into a generic map and persisted without applying the typed validation model.",
    Severity::High,
    &[],
    Some("Bind into a validated struct or perform explicit field validation before persistence."),
);

pub(super) const META_CWE_1125: RuleMetadata = emit::rule_meta(
    "CWE-1125",
    "Excessive public attack surface is mounted without authentication",
    "Debug, admin, or internal maintenance endpoints are registered directly on the public router.",
    Severity::High,
    &[],
    Some(
        "Expose only the minimum route surface publicly and gate administrative endpoints behind dedicated authorization.",
    ),
);

pub(super) const META_CWE_1204: RuleMetadata = emit::rule_meta(
    "CWE-1204",
    "CBC encryption reuses a static initialization vector",
    "A fixed IV literal is reused across requests instead of generating a fresh random IV per ciphertext.",
    Severity::High,
    &[],
    Some(
        "Generate a unique random IV for each encryption operation and include it alongside the ciphertext.",
    ),
);

pub(super) const META_CWE_1220: RuleMetadata = emit::rule_meta(
    "CWE-1220",
    "Record reads are only authenticated, not owner-scoped",
    "Any authenticated caller can fetch arbitrary invoice records because the lookup omits owner scoping.",
    Severity::High,
    &[],
    Some(
        "Include the authenticated principal in the data access predicate, not just a coarse login check.",
    ),
);

pub(super) const META_CWE_1230: RuleMetadata = emit::rule_meta(
    "CWE-1230",
    "Redacted response still leaks sensitive document metadata",
    "A download response omits content but still returns the original filename or file size metadata.",
    Severity::Warning,
    &[],
    Some(
        "Strip sensitive metadata from redacted responses and return only the minimum transport headers needed.",
    ),
);

pub(super) const META_CWE_1236: RuleMetadata = emit::rule_meta(
    "CWE-1236",
    "CSV export writes untrusted cells without formula neutralization",
    "User-controlled text is emitted directly into CSV cells that spreadsheet software may interpret as formulas.",
    Severity::High,
    &[],
    Some("Neutralize dangerous leading characters before writing untrusted data into CSV fields."),
);

pub(super) const META_CWE_1240: RuleMetadata = emit::rule_meta(
    "CWE-1240",
    "Custom XOR cipher is used for token protection",
    "Session tokens are sealed with a homegrown XOR primitive instead of a standard authenticated cipher.",
    Severity::High,
    &[],
    Some(
        "Use a standard authenticated encryption primitive such as AES-GCM instead of custom ciphers.",
    ),
);

pub(super) const META_CWE_1265: RuleMetadata = emit::rule_meta(
    "CWE-1265",
    "Non-reentrant balance update is invoked while its mutex is already held",
    "A transfer path acquires a mutex and then re-enters a helper that acquires the same mutex again.",
    Severity::High,
    &[],
    Some(
        "Keep the lock scope in one place or move the shared helper outside the locked section to avoid nested acquisition.",
    ),
);

pub(super) const META_CWE_1286: RuleMetadata = emit::rule_meta(
    "CWE-1286",
    "JSON configuration is accepted without strict syntax validation",
    "Configuration input is unmarshaled directly without unknown-field rejection or URL syntax validation.",
    Severity::Warning,
    &[],
    Some(
        "Use a strict decoder and validate structural fields before persisting configuration input.",
    ),
);

pub(super) const META_CWE_1289: RuleMetadata = emit::rule_meta(
    "CWE-1289",
    "Literal path comparison is used instead of canonical equivalence checks",
    "A protected asset path is denied only by literal comparison before normalization, allowing equivalent bypass forms.",
    Severity::High,
    &[],
    Some(
        "Normalize the full path and enforce a canonical prefix constraint before serving the resource.",
    ),
);

pub(super) const META_CWE_1322: RuleMetadata = emit::rule_meta(
    "CWE-1322",
    "Async worker blocks its event loop with sleep calls",
    "A queued worker uses blocking sleep inside the loop instead of scheduling retries asynchronously.",
    Severity::Warning,
    &[],
    Some(
        "Schedule retries with timers or separate workers instead of blocking the event loop with sleep.",
    ),
);

pub(super) const META_CWE_1327: RuleMetadata = emit::rule_meta(
    "CWE-1327",
    "Service binds to all interfaces by default",
    "The server listens on :9090 or equivalent, exposing the process on every network interface.",
    Severity::High,
    &[],
    Some("Bind administrative or local-only services to loopback or a tightly scoped interface."),
);

pub(super) const META_CWE_1333: RuleMetadata = emit::rule_meta(
    "CWE-1333",
    "Nested-quantifier regex is applied to unbounded input",
    "A catastrophic backtracking pattern validates user input without a tight length limit.",
    Severity::High,
    &[],
    Some(
        "Use linear-time validation patterns plus explicit length limits for attacker-controlled input.",
    ),
);

pub(super) const META_CWE_1389: RuleMetadata = emit::rule_meta(
    "CWE-1389",
    "Numeric parser accepts alternate radices unexpectedly",
    "A base-0 integer parse accepts octal or hexadecimal prefixes where only decimal counts were intended.",
    Severity::Warning,
    &[],
    Some("Use explicit base-10 parsing when the input contract is decimal-only."),
);

pub(super) const META_CWE_1392: RuleMetadata = emit::rule_meta(
    "CWE-1392",
    "Bootstrap path seeds a default administrator password",
    "Administrative account initialization uses the literal password 'admin' instead of runtime secrets.",
    Severity::Critical,
    &[],
    Some(
        "Require bootstrap credentials from secret-backed configuration and avoid shipping default passwords.",
    ),
);

pub(super) const META_CWE_807: RuleMetadata = emit::rule_meta(
    "CWE-807",
    "Security decision trusts a spoofable client header",
    "Authorization or blocking logic uses a client-controlled forwarded IP header instead of a trusted connection address.",
    Severity::High,
    &[],
    Some(
        "Make security decisions from trusted connection metadata rather than spoofable request headers.",
    ),
);
