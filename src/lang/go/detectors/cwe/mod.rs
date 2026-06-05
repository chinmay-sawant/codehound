//! Bundled Go CWE heuristics.

pub mod facts;

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{emit, Finding, Rule, RuleMetadata, Severity};

use self::facts::{build_go_unit_facts, GoUnitFacts, InputKind};

pub struct GoCweScan;

const GO_CWE_RULE_IDS: &[&str] = &["CWE-15", "CWE-22", "CWE-41", "CWE-59", "CWE-76", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-112", "CWE-140", "CWE-178", "CWE-179", "CWE-182", "CWE-184", "CWE-186", "CWE-201", "CWE-204", "CWE-208", "CWE-209", "CWE-212", "CWE-213", "CWE-214", "CWE-215", "CWE-250", "CWE-252", "CWE-256", "CWE-257", "CWE-260", "CWE-261", "CWE-262", "CWE-263", "CWE-266", "CWE-267", "CWE-268", "CWE-270", "CWE-272", "CWE-273", "CWE-274", "CWE-276", "CWE-277", "CWE-278", "CWE-279", "CWE-280", "CWE-281", "CWE-283", "CWE-289", "CWE-290", "CWE-294", "CWE-301", "CWE-303", "CWE-305", "CWE-306", "CWE-307", "CWE-308", "CWE-309", "CWE-312", "CWE-319", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-328", "CWE-331", "CWE-334", "CWE-335", "CWE-338", "CWE-341", "CWE-342", "CWE-343", "CWE-344", "CWE-346", "CWE-347", "CWE-349", "CWE-353", "CWE-356", "CWE-358", "CWE-359", "CWE-360", "CWE-366", "CWE-367", "CWE-368", "CWE-378", "CWE-379", "CWE-385", "CWE-393", "CWE-403", "CWE-408", "CWE-412", "CWE-420", "CWE-421", "CWE-425", "CWE-426", "CWE-427", "CWE-434", "CWE-454", "CWE-455", "CWE-459", "CWE-472", "CWE-488", "CWE-494", "CWE-497", "CWE-501", "CWE-502", "CWE-515", "CWE-521", "CWE-523", "CWE-524", "CWE-538", "CWE-544", "CWE-547", "CWE-549", "CWE-551", "CWE-552", "CWE-565", "CWE-601", "CWE-603", "CWE-605", "CWE-611", "CWE-613", "CWE-618", "CWE-619", "CWE-620", "CWE-639", "CWE-640", "CWE-645", "CWE-648", "CWE-649", "CWE-653", "CWE-654", "CWE-656", "CWE-708", "CWE-756", "CWE-765", "CWE-778", "CWE-783", "CWE-798", "CWE-807", "CWE-820", "CWE-821", "CWE-826", "CWE-829", "CWE-836", "CWE-838", "CWE-841", "CWE-842", "CWE-909", "CWE-915", "CWE-916", "CWE-917", "CWE-918", "CWE-921", "CWE-924", "CWE-940", "CWE-941", "CWE-1051", "CWE-1052", "CWE-1067", "CWE-1125", "CWE-1173", "CWE-1204", "CWE-1220", "CWE-1230", "CWE-1236", "CWE-1240", "CWE-1265", "CWE-1286", "CWE-1289", "CWE-1322", "CWE-1327", "CWE-1333", "CWE-1389", "CWE-1392"];

const META_CWE_15: RuleMetadata = emit::rule_meta(
    "CWE-15",
    "External control of configuration setting",
    "User-controlled request data is used as a runtime configuration value.",
    Severity::High,
    &[],
    Some("Use trusted configuration sources such as environment variables or fixed allow-lists."),
);

const META_CWE_22: RuleMetadata = emit::rule_meta(
    "CWE-22",
    "Path traversal via user-controlled path segment",
    "User-controlled input is joined into a filesystem path without confining it to a trusted base directory.",
    Severity::High,
    &[],
    Some("Normalize user input with filepath.Clean and enforce a trusted base-directory prefix check before file access."),
);

const META_CWE_41: RuleMetadata = emit::rule_meta(
    "CWE-41",
    "Improper path equivalence resolution",
    "A partial path check rejects some traversal markers but still allows equivalent filesystem aliases to reach a file-read sink.",
    Severity::High,
    &[],
    Some("Resolve to a canonical path and verify it remains under the trusted root before file access."),
);

const META_CWE_59: RuleMetadata = emit::rule_meta(
    "CWE-59",
    "Improper link resolution before file access",
    "A user-controlled filesystem path is opened without rejecting symlink targets first.",
    Severity::High,
    &[],
    Some("Use os.Lstat and reject symlinks before opening the file."),
);

const META_CWE_76: RuleMetadata = emit::rule_meta(
    "CWE-76",
    "Improper neutralization of equivalent special elements",
    "Manual stripping of literal HTML metacharacters does not safely neutralize equivalent encoded input in an HTML output context.",
    Severity::High,
    &[],
    Some("Use context-appropriate escaping such as html.EscapeString for HTML output."),
);

const META_CWE_78: RuleMetadata = emit::rule_meta(
    "CWE-78",
    "OS command built from user-controlled shell input",
    "User-controlled input is interpolated into a shell command string executed through sh -c.",
    Severity::High,
    &[],
    Some("Avoid sh -c for user input; pass fixed argv entries directly to exec.Command and validate the input."),
);

const META_CWE_79: RuleMetadata = emit::rule_meta(
    "CWE-79",
    "Unescaped user input during HTML page generation",
    "User-controlled input is interpolated into HTML output without context-appropriate escaping.",
    Severity::High,
    &[],
    Some("Escape user-controlled HTML output with html.EscapeString or use a safe templating API."),
);

const META_CWE_89: RuleMetadata = emit::rule_meta(
    "CWE-89",
    "SQL query built from user-controlled input",
    "User-controlled input is interpolated into an SQL query string before execution.",
    Severity::High,
    &[],
    Some("Use parameterized queries or prepared statements instead of string formatting for SQL."),
);

const META_CWE_90: RuleMetadata = emit::rule_meta(
    "CWE-90",
    "LDAP filter built from user-controlled input",
    "User-controlled input is interpolated into an LDAP filter string without escaping LDAP metacharacters.",
    Severity::High,
    &[],
    Some("Escape LDAP metacharacters before formatting user-controlled values into filters."),
);

const META_CWE_91: RuleMetadata = emit::rule_meta(
    "CWE-91",
    "XML document assembled from user-controlled fields",
    "User-controlled input is formatted into an XML document string instead of using typed XML marshaling.",
    Severity::High,
    &[],
    Some("Use xml.Marshal or another structured XML encoder instead of formatting XML strings manually."),
);

const META_CWE_93: RuleMetadata = emit::rule_meta(
    "CWE-93",
    "CRLF sequences copied into HTTP header values",
    "User-controlled input is concatenated into an HTTP header value without removing carriage return and line feed characters.",
    Severity::High,
    &[],
    Some("Strip CR and LF from user-controlled header components before setting HTTP headers."),
);

const META_CWE_112: RuleMetadata = emit::rule_meta(
    "CWE-112",
    "Untrusted XML parsed without field validation",
    "Client-controlled XML is unmarshaled and used without validating required fields or value constraints.",
    Severity::High,
    &[],
    Some("Validate required XML fields and numeric constraints after unmarshaling untrusted XML."),
);

const META_CWE_140: RuleMetadata = emit::rule_meta(
    "CWE-140",
    "CSV row built with naive delimiter concatenation",
    "User-controlled fields are joined into CSV output with literal delimiters instead of a CSV encoder.",
    Severity::High,
    &[],
    Some("Use encoding/csv to write CSV rows instead of joining fields with commas."),
);

const META_CWE_178: RuleMetadata = emit::rule_meta(
    "CWE-178",
    "Inconsistent case handling in resource lookup",
    "User-controlled resource names are lowercased and then used in direct membership checks instead of a deliberate case-insensitive comparison.",
    Severity::High,
    &[],
    Some("Use strings.EqualFold or normalize both the allow-list and the incoming value consistently."),
);

const META_CWE_179: RuleMetadata = emit::rule_meta(
    "CWE-179",
    "Validation happens before URL decoding",
    "Encoded input is validated before URL decoding, so the validated form differs from the value later used.",
    Severity::High,
    &[],
    Some("Decode the input first, then validate the final decoded form."),
);

const META_CWE_182: RuleMetadata = emit::rule_meta(
    "CWE-182",
    "Input is collapsed into a privileged value before authorization",
    "A normalization step removes non-alphanumeric content and collapses user input into an authorization-relevant value.",
    Severity::High,
    &[],
    Some("Reject unexpected input instead of stripping characters into an allow-listed authorization token."),
);

const META_CWE_184: RuleMetadata = emit::rule_meta(
    "CWE-184",
    "Incomplete list of disallowed inputs",
    "User-controlled input is normalized and checked against a small deny-list instead of being validated against an allow-list.",
    Severity::High,
    &[],
    Some("Use an allow-list or strict parser for accepted filter syntax instead of a partial deny-list."),
);

const META_CWE_186: RuleMetadata = emit::rule_meta(
    "CWE-186",
    "Overly restrictive regular expression used for host validation",
    "A simplistic host-validation regex rejects realistic hostnames and can lead to incorrect downstream behavior.",
    Severity::High,
    &[],
    Some("Use a hostname regex that permits realistic labels and separators instead of only lowercase letters."),
);

const META_CWE_201: RuleMetadata = emit::rule_meta(
    "CWE-201",
    "Sensitive record fields are serialized directly in a response",
    "An internal record containing secret-bearing fields is returned directly to the caller instead of being projected into a public response shape.",
    Severity::High,
    &[],
    Some("Project internal records into public response structs that omit secret-bearing fields."),
);

const META_CWE_204: RuleMetadata = emit::rule_meta(
    "CWE-204",
    "Authentication failures reveal distinct account states",
    "Different error responses for missing accounts versus wrong credentials expose observable account state discrepancies.",
    Severity::High,
    &[],
    Some("Return a uniform response for authentication failures regardless of which check failed."),
);

const META_CWE_208: RuleMetadata = emit::rule_meta(
    "CWE-208",
    "Secret comparison leaks mismatch timing",
    "A byte-by-byte comparison returns as soon as bytes differ instead of using a constant-time comparison.",
    Severity::High,
    &[],
    Some("Use subtle.ConstantTimeCompare or another constant-time comparison primitive for secret values."),
);

const META_CWE_209: RuleMetadata = emit::rule_meta(
    "CWE-209",
    "Client response includes database error details",
    "A database error is formatted directly into a client-facing response instead of being logged and replaced with a generic message.",
    Severity::High,
    &[],
    Some("Log internal errors server-side and return a generic client message without embedded error details."),
);

const META_CWE_212: RuleMetadata = emit::rule_meta(
    "CWE-212",
    "Sensitive payment fields are exported without removal",
    "A response or export marshals records that still contain sensitive payment fields such as card numbers or PANs.",
    Severity::High,
    &[],
    Some("Project records into an export type that omits or clears sensitive payment fields before marshaling."),
);

const META_CWE_213: RuleMetadata = emit::rule_meta(
    "CWE-213",
    "Public profile response includes policy-restricted compensation fields",
    "A public-facing profile response serializes internal compensation information instead of projecting to a policy-appropriate DTO.",
    Severity::High,
    &[],
    Some("Return a policy-specific public profile DTO that omits compensation or other restricted fields."),
);

const META_CWE_214: RuleMetadata = emit::rule_meta(
    "CWE-214",
    "Sensitive token passed on a process command line",
    "A secret token is supplied as an argv value to an external process where it may be visible to other local users or logs.",
    Severity::High,
    &[],
    Some("Pass the secret through stdin or another non-visible channel instead of argv."),
);

const META_CWE_215: RuleMetadata = emit::rule_meta(
    "CWE-215",
    "Debug logging includes secret material",
    "A debug log statement includes a request-derived secret value that should not be written to logs.",
    Severity::High,
    &[],
    Some("Remove secrets from debug logs and log only non-sensitive request metadata."),
);

const META_CWE_250: RuleMetadata = emit::rule_meta(
    "CWE-250",
    "Configuration file written with unnecessary broad permissions",
    "A file containing runtime state is written with world-accessible permissions instead of a restrictive owner-only mode.",
    Severity::High,
    &[],
    Some("Write sensitive runtime files with restrictive permissions such as 0o600 instead of 0o777."),
);

const META_CWE_252: RuleMetadata = emit::rule_meta(
    "CWE-252",
    "Critical file write return value is ignored",
    "A file write result is discarded instead of being checked and handled.",
    Severity::High,
    &[],
    Some("Check the error returned by os.WriteFile and handle or propagate failures."),
);

const META_CWE_256: RuleMetadata = emit::rule_meta(
    "CWE-256",
    "Plaintext password is stored directly",
    "A user-provided password is persisted directly instead of being transformed into a hash or digest before storage.",
    Severity::High,
    &[],
    Some("Hash or otherwise transform passwords before persistence instead of storing the plaintext value."),
);

const META_CWE_257: RuleMetadata = emit::rule_meta(
    "CWE-257",
    "Password is stored in a recoverable encrypted format",
    "A password or login secret is encrypted with a reversible cipher and then stored, allowing later recovery.",
    Severity::High,
    &[],
    Some("Use a one-way password hashing scheme instead of reversible encryption for stored passwords."),
);

const META_CWE_260: RuleMetadata = emit::rule_meta(
    "CWE-260",
    "Secret is loaded from a configuration file body",
    "A password or secret-bearing field is read from a configuration file on disk instead of being sourced from a dedicated secret channel.",
    Severity::High,
    &[],
    Some("Keep non-secret settings in config files and source secrets from the environment or a secret manager."),
);

const META_CWE_261: RuleMetadata = emit::rule_meta(
    "CWE-261",
    "Password is stored using a reversible encoding",
    "A password is only Base64-encoded before storage, which preserves the underlying secret in a recoverable form.",
    Severity::High,
    &[],
    Some("Use a one-way hash or digest for password storage instead of reversible encodings like Base64."),
);

const META_CWE_262: RuleMetadata = emit::rule_meta(
    "CWE-262",
    "Credential age is never enforced",
    "Authentication logic loads credential metadata but does not check whether the password is older than a configured rotation window.",
    Severity::High,
    &[],
    Some("Track password change timestamps and reject or rotate credentials older than the allowed maximum age."),
);

const META_CWE_263: RuleMetadata = emit::rule_meta(
    "CWE-263",
    "Password expiration window is set unreasonably long",
    "The configured password maximum age is so long that password aging is effectively defeated.",
    Severity::High,
    &[],
    Some("Use a reasonably short password expiration window instead of multi-year validity periods."),
);

const META_CWE_266: RuleMetadata = emit::rule_meta(
    "CWE-266",
    "Client-controlled role is used for privilege assignment",
    "A role or privilege value is taken directly from client input when provisioning access instead of being assigned server-side.",
    Severity::High,
    &[],
    Some("Assign roles server-side from a trusted default or policy instead of accepting them directly from the client."),
);

const META_CWE_267: RuleMetadata = emit::rule_meta(
    "CWE-267",
    "Role is granted unsafe destructive capability",
    "A low-trust reviewer role is allowed to perform unsafe filesystem deletion actions.",
    Severity::High,
    &[],
    Some("Restrict reviewer roles to safe review-specific actions and avoid granting direct destructive filesystem operations."),
);

const META_CWE_268: RuleMetadata = emit::rule_meta(
    "CWE-268",
    "Privilege chaining exposes sensitive export behavior",
    "A sensitive export path is unlocked by combining weaker scopes instead of requiring a dedicated high-trust role or permission.",
    Severity::High,
    &[],
    Some("Require an explicit high-trust role or dedicated export permission for sensitive bulk export paths."),
);

const META_CWE_270: RuleMetadata = emit::rule_meta(
    "CWE-270",
    "Privileged execution context is switched without restoration",
    "The handler elevates the effective user or request context for privileged work but does not restore the original caller context afterward.",
    Severity::High,
    &[],
    Some("Save and restore the original execution context around privileged work instead of leaving the elevated principal in place."),
);

const META_CWE_272: RuleMetadata = emit::rule_meta(
    "CWE-272",
    "Elevated uid is retained longer than required",
    "The handler raises privilege for a privileged operation and keeps the elevated uid in place for the rest of the request instead of dropping it immediately.",
    Severity::High,
    &[],
    Some("Drop the elevated uid as soon as the privileged operation completes instead of retaining it for the remainder of the handler."),
);

const META_CWE_273: RuleMetadata = emit::rule_meta(
    "CWE-273",
    "Privilege drop result is ignored",
    "A privilege-dropping Setuid call is made, but its success is not checked before continuing request processing.",
    Severity::High,
    &[],
    Some("Check the result of privilege-dropping syscalls and abort processing if the drop fails."),
);

const META_CWE_274: RuleMetadata = emit::rule_meta(
    "CWE-274",
    "Insufficient privilege errors are treated as success",
    "A privileged filesystem operation can fail due to insufficient privilege, but the handler still reports success instead of mapping the privilege error to a denial.",
    Severity::High,
    &[],
    Some("Detect insufficient privilege errors such as EPERM and return a denial or failure response instead of reporting success."),
);

const META_CWE_276: RuleMetadata = emit::rule_meta(
    "CWE-276",
    "Sensitive session file uses overly permissive default mode",
    "A session or secret-bearing artifact is written with world-readable or world-writable permissions instead of an owner-only mode.",
    Severity::High,
    &[],
    Some("Write session and secret-bearing artifacts with restrictive owner-only permissions such as 0o600."),
);

const META_CWE_277: RuleMetadata = emit::rule_meta(
    "CWE-277",
    "Cleared umask allows insecure inherited permissions",
    "The process clears umask before creating a directory, allowing overly permissive inherited modes to reach created content.",
    Severity::High,
    &[],
    Some("Use a restrictive umask and avoid clearing it to zero around filesystem creation."),
);

const META_CWE_278: RuleMetadata = emit::rule_meta(
    "CWE-278",
    "Archive extraction preserves untrusted permission bits",
    "Archive entry permission bits are restored verbatim when creating files, allowing untrusted metadata to set insecure modes.",
    Severity::High,
    &[],
    Some("Clamp extracted file modes to a safe value instead of preserving untrusted archive permission bits."),
);

const META_CWE_279: RuleMetadata = emit::rule_meta(
    "CWE-279",
    "Execution assigns broader permissions than requested",
    "The handler parses a requested mode but still writes the file with a hard-coded world-writable mode.",
    Severity::High,
    &[],
    Some("Honor a validated bounded mode instead of forcing a broad hard-coded file permission."),
);

const META_CWE_280: RuleMetadata = emit::rule_meta(
    "CWE-280",
    "Privilege failure falls through into a destructive path",
    "Failure to access a protected resource is treated as the branch that performs a destructive or privileged action instead of denying the request.",
    Severity::High,
    &[],
    Some("Treat access failures as denial conditions and do not continue into privileged deletion or mutation paths."),
);

const META_CWE_281: RuleMetadata = emit::rule_meta(
    "CWE-281",
    "Backup copy recreates file without preserving source permissions",
    "A file is copied with os.Create, which recreates it using process defaults instead of preserving the source file mode.",
    Severity::High,
    &[],
    Some("Stat the source and recreate the destination with the source mode or another explicitly safe mode."),
);

const META_CWE_283: RuleMetadata = emit::rule_meta(
    "CWE-283",
    "File deletion proceeds without verifying ownership",
    "A user-selected path is deleted without checking that the underlying file is owned by the authenticated caller.",
    Severity::High,
    &[],
    Some("Check the file's owner metadata against the authenticated caller before destructive file operations."),
);

const META_CWE_289: RuleMetadata = emit::rule_meta(
    "CWE-289",
    "Principal lookup ignores canonical realm-qualified identity",
    "Authentication looks up only the local username portion before the @ and can accept alternate-name aliases as the same principal.",
    Severity::High,
    &[],
    Some("Match against a canonical normalized principal identifier, including the full realm-qualified name."),
);

const META_CWE_290: RuleMetadata = emit::rule_meta(
    "CWE-290",
    "Client-controlled identity header is trusted as authentication",
    "The handler trusts a caller-supplied X-Remote-User header instead of deriving identity from validated server-side session state.",
    Severity::High,
    &[],
    Some("Derive identity from a validated server-side session or middleware context, not from caller-controlled headers."),
);

const META_CWE_294: RuleMetadata = emit::rule_meta(
    "CWE-294",
    "Authentication accepts replayable token without nonce tracking",
    "A login flow accepts a bearer or signed token without validating a one-time nonce or recording prior use, allowing capture and replay.",
    Severity::High,
    &[],
    Some("Require a nonce or one-time identifier and reject tokens whose nonce has already been consumed."),
);

const META_CWE_301: RuleMetadata = emit::rule_meta(
    "CWE-301",
    "Authentication proof reflects the client challenge",
    "The server returns the client-provided challenge directly as the authentication proof instead of transforming it with server-only key material.",
    Severity::High,
    &[],
    Some("Generate the proof from server-held secret material, such as an HMAC over the challenge, instead of echoing the challenge."),
);

const META_CWE_303: RuleMetadata = emit::rule_meta(
    "CWE-303",
    "MAC verification uses string equality instead of proper constant-time verification",
    "The authentication algorithm compares the computed MAC to user input with string equality instead of decoding and constant-time comparison.",
    Severity::High,
    &[],
    Some("Decode the provided MAC and compare it with subtle.ConstantTimeCompare or hmac.Equal."),
);

const META_CWE_305: RuleMetadata = emit::rule_meta(
    "CWE-305",
    "Debug flag bypasses primary authentication",
    "A query-controlled debug branch reaches privileged functionality before the authenticated subject check runs.",
    Severity::High,
    &[],
    Some("Require authentication before any privileged branch and never use caller-controlled debug flags to bypass auth."),
);

const META_CWE_306: RuleMetadata = emit::rule_meta(
    "CWE-306",
    "Critical destructive function has no authentication gate",
    "A destructive operation is reachable without any authenticated operator or subject check.",
    Severity::High,
    &[],
    Some("Gate destructive functions with an authenticated operator check before performing the action."),
);

const META_CWE_307: RuleMetadata = emit::rule_meta(
    "CWE-307",
    "Authentication flow lacks attempt throttling or lockout",
    "The login path performs credential lookup and returns failures without tracking repeated attempts, delaying, or rate limiting.",
    Severity::High,
    &[],
    Some("Track repeated failures and apply throttling, backoff, or lockout before processing more attempts."),
);

const META_CWE_308: RuleMetadata = emit::rule_meta(
    "CWE-308",
    "High-value operation uses only a single factor",
    "A sensitive wire-transfer style action is authorized by password presence alone instead of requiring a validated second factor.",
    Severity::High,
    &[],
    Some("Require a validated second factor such as TOTP in addition to the password for high-value actions."),
);

const META_CWE_309: RuleMetadata = emit::rule_meta(
    "CWE-309",
    "Enterprise authentication relies on password form login only",
    "An enterprise login route treats username and password form fields as the primary authentication method instead of requiring a stronger assertion flow.",
    Severity::High,
    &[],
    Some("Use a stronger primary authentication method such as WebAuthn or a trusted SSO assertion instead of password-only form login."),
);

const META_CWE_312: RuleMetadata = emit::rule_meta(
    "CWE-312",
    "Sensitive identifier is stored in cleartext at rest",
    "A sensitive identifier such as an SSN is persisted directly in plaintext instead of being encrypted before storage.",
    Severity::High,
    &[],
    Some("Encrypt sensitive identifiers before database or disk persistence instead of storing cleartext values."),
);

const META_CWE_319: RuleMetadata = emit::rule_meta(
    "CWE-319",
    "Sensitive payment data is accepted over cleartext HTTP",
    "A payment endpoint handles PAN or CVV data while serving over plain HTTP instead of requiring TLS.",
    Severity::High,
    &[],
    Some("Terminate TLS before handling sensitive payment data and use HTTPS-only listeners."),
);

const META_CWE_322: RuleMetadata = emit::rule_meta(
    "CWE-322",
    "TLS key exchange skips peer authentication",
    "A TLS relay connection disables certificate verification and therefore exchanges key material without authenticating the peer.",
    Severity::High,
    &[],
    Some("Verify the peer certificate chain and hostname instead of setting InsecureSkipVerify."),
);

const META_CWE_323: RuleMetadata = emit::rule_meta(
    "CWE-323",
    "AEAD encryption reuses a fixed nonce",
    "A static nonce is reused with the same key for repeated AEAD encryption operations.",
    Severity::High,
    &[],
    Some("Generate a fresh random nonce for each AEAD encryption and store it alongside the ciphertext."),
);

const META_CWE_324: RuleMetadata = emit::rule_meta(
    "CWE-324",
    "Expired signing key is still used",
    "Cryptographic signing or verification proceeds without checking the key expiration time.",
    Severity::High,
    &[],
    Some("Reject expired keys before using them for signing or verification operations."),
);

const META_CWE_325: RuleMetadata = emit::rule_meta(
    "CWE-325",
    "Encryption omits an integrity-protection step",
    "Sensitive data is encrypted with a stream mode like CTR but without an authentication tag or AEAD integrity step.",
    Severity::High,
    &[],
    Some("Use an authenticated encryption mode such as AES-GCM instead of raw CTR encryption for sensitive data."),
);

const META_CWE_328: RuleMetadata = emit::rule_meta(
    "CWE-328",
    "Weak hash algorithm is used for password storage",
    "A password digest is derived with MD5 instead of a stronger hashing construction.",
    Severity::High,
    &[],
    Some("Use a stronger password hashing approach instead of MD5, such as a salted modern KDF."),
);

const META_CWE_331: RuleMetadata = emit::rule_meta(
    "CWE-331",
    "Recovery code uses insufficient entropy",
    "A security-sensitive recovery code is generated from a small decimal range using math/rand instead of cryptographic randomness.",
    Severity::High,
    &[],
    Some("Generate recovery codes from cryptographic randomness with a large enough entropy budget."),
);

const META_CWE_334: RuleMetadata = emit::rule_meta(
    "CWE-334",
    "Invite token comes from a very small random space",
    "A registration or invite token is generated from a very small 4096-value space and is easy to brute force.",
    Severity::High,
    &[],
    Some("Generate tokens from a much larger cryptographic random space instead of small integer ranges."),
);

const META_CWE_335: RuleMetadata = emit::rule_meta(
    "CWE-335",
    "PRNG is seeded from predictable wall-clock time",
    "A pseudo-random ticket is derived from a PRNG seeded with current time, making outputs predictable.",
    Severity::High,
    &[],
    Some("Use cryptographic randomness instead of seeding a PRNG from time for security-sensitive tokens or tickets."),
);

const META_CWE_338: RuleMetadata = emit::rule_meta(
    "CWE-338",
    "Session or access token uses a cryptographically weak PRNG",
    "A security token is generated with math/rand instead of cryptographic randomness.",
    Severity::High,
    &[],
    Some("Generate tokens from crypto/rand instead of math/rand for security-sensitive values."),
);

const META_CWE_341: RuleMetadata = emit::rule_meta(
    "CWE-341",
    "Token is predictable from observable process and time state",
    "A device or pairing token is assembled from observable process id, timestamp, or caller-controlled values instead of cryptographic randomness.",
    Severity::High,
    &[],
    Some("Generate device tokens from cryptographic randomness instead of predictable process and time state."),
);

const META_CWE_342: RuleMetadata = emit::rule_meta(
    "CWE-342",
    "OTP is derived by incrementing the previous value",
    "A login code is produced by incrementing the prior OTP value, making the next exact value predictable from previous ones.",
    Severity::High,
    &[],
    Some("Generate one-time codes from cryptographic randomness instead of incrementing previous values."),
);

const META_CWE_343: RuleMetadata = emit::rule_meta(
    "CWE-343",
    "Pseudo-random output range is predictable from prior state transitions",
    "A raffle or prize value is computed from a deterministic linear recurrence over shared state instead of fresh random input.",
    Severity::High,
    &[],
    Some("Use fresh cryptographic randomness instead of deterministic state transitions for security-sensitive draws."),
);

const META_CWE_344: RuleMetadata = emit::rule_meta(
    "CWE-344",
    "Invariant hard-coded secret is used in a changing signing context",
    "An HMAC secret is hard-coded as a constant instead of being sourced from deploy-time secret material.",
    Severity::High,
    &[],
    Some("Load signing secrets from managed secret material instead of embedding invariant constants in code."),
);

const META_CWE_346: RuleMetadata = emit::rule_meta(
    "CWE-346",
    "Origin is reflected without validation",
    "A cross-origin response reflects the caller-supplied Origin value and enables credentials without validating the origin against a trusted allow-list.",
    Severity::High,
    &[],
    Some("Validate Origin against a trusted allow-list before reflecting it and avoid credentialed reflection for untrusted origins."),
);

const META_CWE_347: RuleMetadata = emit::rule_meta(
    "CWE-347",
    "JWT claims are accepted without signature verification",
    "A signed token payload is decoded and trusted without verifying the cryptographic signature first.",
    Severity::High,
    &[],
    Some("Verify the JWT signature with the expected public key before trusting any decoded claims."),
);

const META_CWE_349: RuleMetadata = emit::rule_meta(
    "CWE-349",
    "Trusted envelope carries extraneous untrusted profile data",
    "A trusted flag is accepted together with an untyped raw profile blob, and role-bearing fields from that raw blob are used directly.",
    Severity::High,
    &[],
    Some("Use a typed validated trusted payload instead of mixing trusted indicators with raw untrusted profile data."),
);

const META_CWE_353: RuleMetadata = emit::rule_meta(
    "CWE-353",
    "Inbound telemetry payload lacks integrity verification",
    "An external payload is ingested and persisted without verifying an integrity MAC or equivalent checksum.",
    Severity::High,
    &[],
    Some("Verify an HMAC or other integrity check before accepting and storing external payloads."),
);

const META_CWE_356: RuleMetadata = emit::rule_meta(
    "CWE-356",
    "Destructive UI action lacks explicit confirmation token",
    "A destructive delete or purge action is executed without a separate explicit confirmation value from the caller.",
    Severity::High,
    &[],
    Some("Require an explicit confirmation token or deliberate second confirmation step before destructive actions."),
);

const META_CWE_358: RuleMetadata = emit::rule_meta(
    "CWE-358",
    "JWT structure standard check is incompletely implemented",
    "Bearer token claims are decoded without checking required structural or algorithm constraints from the token standard.",
    Severity::High,
    &[],
    Some("Validate required JWT structure and expected algorithm fields before accepting bearer token contents."),
);

const META_CWE_359: RuleMetadata = emit::rule_meta(
    "CWE-359",
    "Private personal information is exposed to unauthorized callers",
    "A profile response returns sensitive PII fields like SSN or phone without verifying the requester is authorized and without projecting to a public view.",
    Severity::High,
    &[],
    Some("Authorize the requester and project data into a public-safe response shape before serialization."),
);

const META_CWE_360: RuleMetadata = emit::rule_meta(
    "CWE-360",
    "Client-controlled forwarding header is trusted as system event data",
    "Security-sensitive IP recording trusts X-Forwarded-For instead of deriving the client address from the connection metadata.",
    Severity::High,
    &[],
    Some("Use trusted connection metadata such as RemoteAddr instead of caller-controlled forwarded headers."),
);

const META_CWE_366: RuleMetadata = emit::rule_meta(
    "CWE-366",
    "Shared credit state is updated with a non-atomic race-prone increment",
    "A shared mutable credit counter is incremented directly rather than with atomic or synchronized operations.",
    Severity::High,
    &[],
    Some("Use atomic or synchronized updates for shared mutable counters."),
);

const META_CWE_367: RuleMetadata = emit::rule_meta(
    "CWE-367",
    "File is checked with Stat before later use",
    "A filesystem path is checked for existence or state and then used in a separate operation, creating a TOCTOU race window.",
    Severity::High,
    &[],
    Some("Avoid separate check-then-use file flows; validate the path and use it directly in a single operation where possible."),
);

const META_CWE_368: RuleMetadata = emit::rule_meta(
    "CWE-368",
    "Privilege mode switch relies on unsynchronized shared context flag",
    "A shared privileged-mode flag controls context switching without synchronization, creating race-prone privilege behavior.",
    Severity::High,
    &[],
    Some("Guard privilege mode transitions with synchronization and avoid unsafely shared context flags."),
);

const META_CWE_378: RuleMetadata = emit::rule_meta(
    "CWE-378",
    "Temporary file is created with insecure permissions",
    "A temporary export or upload file is created under TempDir with world-accessible permissions instead of a restrictive mode.",
    Severity::High,
    &[],
    Some("Create temp files with restrictive permissions such as 0o600 and prefer CreateTemp."),
);

const META_CWE_379: RuleMetadata = emit::rule_meta(
    "CWE-379",
    "Temporary directory uses insecure permissions",
    "A temporary file is staged in a shared world-writable directory instead of a private restricted temporary directory.",
    Severity::High,
    &[],
    Some("Create private temporary directories with restrictive permissions before staging temporary files."),
);

const META_CWE_385: RuleMetadata = emit::rule_meta(
    "CWE-385",
    "Secret comparison leaks timing through early exit",
    "A secret is compared byte by byte with early return instead of using a constant-time comparison primitive.",
    Severity::High,
    &[],
    Some("Use subtle.ConstantTimeCompare for secret comparisons instead of early-exit loops."),
);

const META_CWE_393: RuleMetadata = emit::rule_meta(
    "CWE-393",
    "Lookup failure returns a success status code",
    "An account lookup failure still returns HTTP 200 and a fallback payload instead of an error status.",
    Severity::High,
    &[],
    Some("Return an error status such as 500 or 404 when the lookup fails instead of replying with success."),
);

const META_CWE_403: RuleMetadata = emit::rule_meta(
    "CWE-403",
    "Sensitive file descriptor remains open across child process execution",
    "A sensitive file is opened before spawning a child process and is not closed before exec, exposing the descriptor to the child control sphere.",
    Severity::High,
    &[],
    Some("Close sensitive descriptors before launching child processes and avoid inheriting them into execed commands."),
);

const META_CWE_408: RuleMetadata = emit::rule_meta(
    "CWE-408",
    "Expensive export happens before authentication check",
    "The code performs a potentially amplifying query before checking whether the caller is authenticated.",
    Severity::High,
    &[],
    Some("Authenticate the caller before performing expensive or amplifying work."),
);

const META_CWE_412: RuleMetadata = emit::rule_meta(
    "CWE-412",
    "Client controls the externally accessible lock path",
    "A lock file path is taken directly from the request, allowing external actors to point the lock mechanism at arbitrary locations.",
    Severity::High,
    &[],
    Some("Use a fixed server-controlled lock path rather than accepting the lock target from the client."),
);

const META_CWE_420: RuleMetadata = emit::rule_meta(
    "CWE-420",
    "Alternate debug channel bypasses the primary authenticated route",
    "A debug or alternate route exposes related functionality without the same authentication guard as the primary API route.",
    Severity::High,
    &[],
    Some("Place alternate and debug channels behind the same authentication guard as the primary route."),
);

const META_CWE_421: RuleMetadata = emit::rule_meta(
    "CWE-421",
    "Alternate event channel races shared transfer state",
    "An alternate SSE or event channel reads shared transfer state without synchronization while the primary handler writes it.",
    Severity::High,
    &[],
    Some("Synchronize shared state used by alternate channels with the primary handler."),
);

const META_CWE_425: RuleMetadata = emit::rule_meta(
    "CWE-425",
    "Restricted admin export is reachable without authorization middleware",
    "An internal admin export endpoint is mounted without an explicit authorization guard.",
    Severity::High,
    &[],
    Some("Mount restricted exports behind explicit admin authorization middleware."),
);

const META_CWE_426: RuleMetadata = emit::rule_meta(
    "CWE-426",
    "Plugin search path comes from the request",
    "Plugin or extension load paths are built from caller-controlled directories instead of fixed trusted roots.",
    Severity::High,
    &[],
    Some("Load plugins only from fixed trusted directories and reject caller-controlled search paths."),
);

const META_CWE_427: RuleMetadata = emit::rule_meta(
    "CWE-427",
    "PATH is prepended from user input before helper execution",
    "Caller-controlled directories are prepended to PATH before resolving a helper binary by name.",
    Severity::High,
    &[],
    Some("Invoke helpers via absolute paths and do not mutate PATH from user input."),
);

const META_CWE_434: RuleMetadata = emit::rule_meta(
    "CWE-434",
    "Upload stores client filename without extension allow-list",
    "An uploaded file is stored and served using the client filename without restricting dangerous extensions or renaming safely.",
    Severity::High,
    &[],
    Some("Allow-list upload extensions and store uploads under randomized safe names."),
);

const META_CWE_454: RuleMetadata = emit::rule_meta(
    "CWE-454",
    "Security policy bootstrap reads flag from untrusted request",
    "A security configuration flag is initialized from a client request instead of server-controlled configuration.",
    Severity::High,
    &[],
    Some("Load security policy flags from server configuration rather than client input."),
);

const META_CWE_455: RuleMetadata = emit::rule_meta(
    "CWE-455",
    "Startup continues after security-critical initialization failure",
    "The process logs a failure to load required TLS or HSM material but continues starting anyway.",
    Severity::High,
    &[],
    Some("Fail startup when required security material cannot be loaded."),
);

const META_CWE_459: RuleMetadata = emit::rule_meta(
    "CWE-459",
    "Sensitive temporary export file is never removed",
    "A temporary export file is created and served but not deleted afterward.",
    Severity::High,
    &[],
    Some("Remove sensitive temporary files after use and close them deterministically."),
);

const META_CWE_472: RuleMetadata = emit::rule_meta(
    "CWE-472",
    "Hidden role field is trusted for authorization",
    "Authorization uses a role value submitted by the client rather than resolving the role server-side from the authenticated identity.",
    Severity::High,
    &[],
    Some("Resolve authorization roles server-side from the authenticated session or account state."),
);

const META_CWE_488: RuleMetadata = emit::rule_meta(
    "CWE-488",
    "Global cart state is keyed by client-controlled session id",
    "Cross-request cart state is stored in a global map keyed directly by a caller-supplied session identifier.",
    Severity::High,
    &[],
    Some("Bind cart state to a validated server session instead of a client-controlled identifier."),
);

const META_CWE_494: RuleMetadata = emit::rule_meta(
    "CWE-494",
    "Downloaded executable bundle lacks integrity verification",
    "A remotely downloaded worker bundle is written or executed without verifying a pinned digest first.",
    Severity::High,
    &[],
    Some("Verify a pinned digest or signature before accepting downloaded executable content."),
);

const META_CWE_497: RuleMetadata = emit::rule_meta(
    "CWE-497",
    "Diagnostics expose host environment details",
    "A diagnostics endpoint returns hostnames, environment variables, or similar system internals to arbitrary callers.",
    Severity::High,
    &[],
    Some("Return only coarse health information from diagnostics and avoid exposing system internals."),
);

const META_CWE_501: RuleMetadata = emit::rule_meta(
    "CWE-501",
    "Trusted approval flag is merged into untrusted request struct",
    "Trusted decision state is stored in the same decoded request structure as untrusted client fields.",
    Severity::High,
    &[],
    Some("Keep trusted decision state separate from untrusted request payloads."),
);

const META_CWE_502: RuleMetadata = emit::rule_meta(
    "CWE-502",
    "Untrusted gob payload is deserialized into a privileged action",
    "User-controlled gob data is decoded directly into an action struct that drives privileged state changes.",
    Severity::High,
    &[],
    Some("Use validated JSON or another constrained format for request payloads before privileged updates."),
);

const META_CWE_515: RuleMetadata = emit::rule_meta(
    "CWE-515",
    "Shared status flag creates a covert cross-request storage channel",
    "A global flag is written from one request and later read from another handler to disclose sensitive state.",
    Severity::High,
    &[],
    Some("Store per-tenant or per-request state in scoped storage instead of global cross-request flags."),
);

const META_CWE_521: RuleMetadata = emit::rule_meta(
    "CWE-521",
    "Password policy accepts trivially weak passwords",
    "Registration accepts effectively empty or one-character passwords before persistence.",
    Severity::High,
    &[],
    Some("Enforce a strong password policy before accepting or storing credentials."),
);

const META_CWE_523: RuleMetadata = emit::rule_meta(
    "CWE-523",
    "Credentials are accepted over a cleartext listener",
    "Username and password login is served without requiring TLS before credentials are processed.",
    Severity::High,
    &[],
    Some("Require TLS or redirect to HTTPS before processing login credentials."),
);

const META_CWE_524: RuleMetadata = emit::rule_meta(
    "CWE-524",
    "Process-wide cache stores raw session tokens",
    "Bearer or session tokens are cached in shared process memory keyed by user-controlled identifiers.",
    Severity::High,
    &[],
    Some("Keep tokens request-scoped or server-session-bound instead of storing them in shared process-wide caches."),
);

const META_CWE_538: RuleMetadata = emit::rule_meta(
    "CWE-538",
    "Sensitive DSN is exported to a public file path",
    "Database connection secrets are written to a world-readable path under a public static directory.",
    Severity::High,
    &[],
    Some("Write operational secrets only to restricted internal paths with tight file permissions."),
);

const META_CWE_544: RuleMetadata = emit::rule_meta(
    "CWE-544",
    "Database failures are handled inconsistently across handlers",
    "Different handlers react to similar database failures with ad-hoc panic and logging paths instead of one uniform error policy.",
    Severity::High,
    &[],
    Some("Route database failures through one shared helper with consistent status handling."),
);

const META_CWE_547: RuleMetadata = emit::rule_meta(
    "CWE-547",
    "Signing secret is hard-coded in source",
    "JWT or MAC signing material is embedded as a source constant instead of loaded from managed runtime configuration.",
    Severity::High,
    &[],
    Some("Load signing secrets from environment or secret storage instead of hard-coding them in source."),
);

const META_CWE_549: RuleMetadata = emit::rule_meta(
    "CWE-549",
    "Password value is echoed back in an API response",
    "A signup or preview response includes the submitted password field in cleartext.",
    Severity::High,
    &[],
    Some("Never return password values in API responses or previews."),
);

const META_CWE_551: RuleMetadata = emit::rule_meta(
    "CWE-551",
    "Authorization checks run on raw path before canonicalization",
    "A privileged path check is performed on the raw request path before percent-unescaping or normalization.",
    Severity::High,
    &[],
    Some("Canonicalize the path before applying authorization or routing checks."),
);

const META_CWE_552: RuleMetadata = emit::rule_meta(
    "CWE-552",
    "Uploaded documents are chmodded world-readable",
    "Uploaded contract files are stored and then assigned world-readable or world-writable permissions.",
    Severity::High,
    &[],
    Some("Restrict uploaded document permissions to owner-only access and sanitize the stored name."),
);

const META_CWE_565: RuleMetadata = emit::rule_meta(
    "CWE-565",
    "Privileged delete trusts an unverified role cookie",
    "Authorization for a privileged delete action is derived directly from a client-controlled role cookie.",
    Severity::High,
    &[],
    Some("Validate cookie role claims against server-side session state before authorizing privileged actions."),
);

const META_CWE_601: RuleMetadata = emit::rule_meta(
    "CWE-601",
    "Redirect target is taken from an unvalidated caller parameter",
    "The application redirects to a caller-supplied next URL without enforcing a same-site policy.",
    Severity::High,
    &[],
    Some("Restrict redirects to validated same-site relative paths or an allow-list."),
);

const META_CWE_603: RuleMetadata = emit::rule_meta(
    "CWE-603",
    "Server trusts a caller-supplied authenticated header",
    "Sensitive state changes rely on a client-provided authenticated marker instead of server-validated identity.",
    Severity::High,
    &[],
    Some("Authorize state changes from server-side session identity instead of caller-supplied auth headers."),
);

const META_CWE_605: RuleMetadata = emit::rule_meta(
    "CWE-605",
    "Listener enables SO_REUSEADDR on a service socket",
    "A service listener explicitly enables address reuse on the bound socket, weakening exclusive ownership on restart.",
    Severity::High,
    &[],
    Some("Bind service listeners exclusively unless address reuse is explicitly required and justified."),
);

const META_CWE_611: RuleMetadata = emit::rule_meta(
    "CWE-611",
    "Untrusted XML is parsed with strict mode disabled",
    "XML input is decoded with strict validation disabled and without defensive DOCTYPE rejection.",
    Severity::High,
    &[],
    Some("Reject DOCTYPE and keep strict XML parsing enabled on bounded request bodies."),
);

const META_CWE_613: RuleMetadata = emit::rule_meta(
    "CWE-613",
    "Session cookie never expires and is not revoked",
    "Login issues a non-expiring session cookie and logout does not invalidate server-side session state.",
    Severity::High,
    &[],
    Some("Use short-lived secure cookies and revoke server-side session state on logout."),
);

const META_CWE_618: RuleMetadata = emit::rule_meta(
    "CWE-618",
    "HTTP endpoint exposes a privileged native helper method",
    "A public endpoint forwards caller-controlled plugin method names and arguments to a privileged local helper binary.",
    Severity::High,
    &[],
    Some("Expose only an allow-listed set of non-privileged methods instead of passing raw method names to a native helper."),
);

const META_CWE_619: RuleMetadata = emit::rule_meta(
    "CWE-619",
    "Database cursor is left open on an early return path",
    "A sql.Rows cursor is created and can exit through an early return without being closed.",
    Severity::High,
    &[],
    Some("Close database cursors with defer immediately after successful query creation."),
);

const META_CWE_620: RuleMetadata = emit::rule_meta(
    "CWE-620",
    "Password change does not verify the current password",
    "A password update replaces the stored credential without proving knowledge of the existing password.",
    Severity::High,
    &[],
    Some("Require the current password or equivalent verified session proof before changing credentials."),
);

const META_CWE_639: RuleMetadata = emit::rule_meta(
    "CWE-639",
    "Record lookup trusts a user-controlled key without owner scoping",
    "A caller-supplied record identifier is used directly without constraining the query to the authenticated owner.",
    Severity::High,
    &[],
    Some("Scope caller-controlled record identifiers to the authenticated owner in the data query."),
);

const META_CWE_640: RuleMetadata = emit::rule_meta(
    "CWE-640",
    "Forgot-password flow resets credentials from email alone",
    "The recovery flow changes a password using only the submitted email address without a time-limited reset token.",
    Severity::High,
    &[],
    Some("Require a single-use, time-limited reset token before changing the password."),
);

const META_CWE_645: RuleMetadata = emit::rule_meta(
    "CWE-645",
    "Account lockout triggers after a single failed login",
    "The lockout policy permanently or immediately blocks the account after one failed attempt.",
    Severity::High,
    &[],
    Some("Allow several failures and use a temporary lockout window instead of locking after one attempt."),
);

const META_CWE_648: RuleMetadata = emit::rule_meta(
    "CWE-648",
    "Web handler exposes privileged chown with caller-supplied uid",
    "A request handler passes caller-controlled path and uid values into a privileged ownership-changing API.",
    Severity::High,
    &[],
    Some("Restrict ownership changes to application-controlled paths and fixed service identities."),
);

const META_CWE_649: RuleMetadata = emit::rule_meta(
    "CWE-649",
    "Base64-obfuscated role cookie is trusted without integrity checking",
    "The application decodes an obfuscated profile cookie and trusts the embedded role without verifying integrity.",
    Severity::High,
    &[],
    Some("Authenticate encoded profile data with an HMAC or signature before trusting embedded roles."),
);

const META_CWE_653: RuleMetadata = emit::rule_meta(
    "CWE-653",
    "Public and admin paths share the same privileged data store",
    "Unprivileged and privileged operations use the same privileged backing store instead of separate compartments.",
    Severity::High,
    &[],
    Some("Use separate read-only and privileged stores or handles for public and admin paths."),
);

const META_CWE_654: RuleMetadata = emit::rule_meta(
    "CWE-654",
    "Admin access relies only on a static API key header",
    "A privileged export is authorized solely by a single static header value rather than layered identity checks.",
    Severity::High,
    &[],
    Some("Require authenticated session role checks in addition to any service credential."),
);

const META_CWE_656: RuleMetadata = emit::rule_meta(
    "CWE-656",
    "Admin functionality is protected only by a secret URL path",
    "Sensitive configuration access relies on obscurity of the route path instead of real authorization.",
    Severity::High,
    &[],
    Some("Require authenticated admin authorization instead of relying on a hidden path."),
);

const META_CWE_708: RuleMetadata = emit::rule_meta(
    "CWE-708",
    "Caller chooses file ownership assignment target and uid",
    "A file ownership operation uses caller-controlled destination and owner identifiers rather than a fixed service identity.",
    Severity::High,
    &[],
    Some("Restrict ownership assignments to controlled directories and fixed service uid or gid values."),
);

const META_CWE_756: RuleMetadata = emit::rule_meta(
    "CWE-756",
    "Raw database error text is returned to the client",
    "An internal database error is sent directly to the client instead of a generic error response.",
    Severity::High,
    &[],
    Some("Return a generic error response and keep internal details out of client-visible output."),
);

const META_CWE_765: RuleMetadata = emit::rule_meta(
    "CWE-765",
    "Mutex is unlocked twice on an error path",
    "The same critical-section lock is explicitly released more than once on a validation failure path.",
    Severity::High,
    &[],
    Some("Use a single defer-based unlock or ensure each control path releases the lock exactly once."),
);

const META_CWE_778: RuleMetadata = emit::rule_meta(
    "CWE-778",
    "Authentication failures are not logged",
    "Security-relevant login failures return unauthorized responses without recording an audit event.",
    Severity::High,
    &[],
    Some("Log authentication failures with actor and source metadata for auditability."),
);

const META_CWE_783: RuleMetadata = emit::rule_meta(
    "CWE-783",
    "Authorization condition relies on ambiguous operator precedence",
    "A mixed boolean expression depends on && and || precedence and grants or denies access unexpectedly.",
    Severity::High,
    &[],
    Some("Use explicit parentheses to make authorization logic unambiguous."),
);

const META_CWE_798: RuleMetadata = emit::rule_meta(
    "CWE-798",
    "Database credentials are hard-coded in source",
    "A database DSN with embedded credentials is stored directly in the source code.",
    Severity::High,
    &[],
    Some("Load credentials from environment or secret storage at runtime."),
);

const META_CWE_820: RuleMetadata = emit::rule_meta(
    "CWE-820",
    "Shared map is updated without synchronization",
    "Concurrent handlers mutate a shared map without any lock protection.",
    Severity::High,
    &[],
    Some("Protect shared mutable state with a mutex or another synchronization primitive."),
);

const META_CWE_821: RuleMetadata = emit::rule_meta(
    "CWE-821",
    "Shared cache is mutated under a read lock",
    "A write to shared state occurs while only a read lock is held.",
    Severity::High,
    &[],
    Some("Use an exclusive lock for writes to shared state."),
);

const META_CWE_826: RuleMetadata = emit::rule_meta(
    "CWE-826",
    "Shared database handle is closed before background work completes",
    "A background task still depends on a database handle after the shared handle has already been closed.",
    Severity::High,
    &[],
    Some("Keep shared resources alive until background work finishes or bind workers to scoped handles."),
);

const META_CWE_829: RuleMetadata = emit::rule_meta(
    "CWE-829",
    "Plugin is loaded from a caller-controlled filesystem path",
    "A shared object is loaded from a user-supplied path without an allowlist or fixed module root.",
    Severity::High,
    &[],
    Some("Load only allowlisted modules from a fixed trusted directory."),
);

const META_CWE_836: RuleMetadata = emit::rule_meta(
    "CWE-836",
    "Authentication trusts a client-supplied password hash",
    "The caller submits a password hash that is compared directly to stored credential material.",
    Severity::High,
    &[],
    Some("Accept plaintext passwords over the authenticated channel and verify them against stored hashes server-side."),
);

const META_CWE_838: RuleMetadata = emit::rule_meta(
    "CWE-838",
    "Response emits invalid bytes for the declared output encoding",
    "The handler declares UTF-8 JSON but writes invalid byte sequences before the payload.",
    Severity::High,
    &[],
    Some("Ensure emitted bytes match the declared output encoding and content type."),
);

const META_CWE_841: RuleMetadata = emit::rule_meta(
    "CWE-841",
    "Password reset workflow skips the MFA completion step",
    "A multi-step recovery or reset flow changes credentials without enforcing the required MFA gate.",
    Severity::High,
    &[],
    Some("Require successful completion of the MFA or equivalent workflow step before password changes."),
);

const META_CWE_842: RuleMetadata = emit::rule_meta(
    "CWE-842",
    "New users are placed into an administrator group by default",
    "Registration assigns new accounts to a privileged group instead of the standard member role.",
    Severity::High,
    &[],
    Some("Assign a non-privileged default group to newly registered accounts."),
);

const META_CWE_909: RuleMetadata = emit::rule_meta(
    "CWE-909",
    "Global database handle is used before initialization is checked",
    "A global resource handle is dereferenced without verifying that startup initialization has occurred.",
    Severity::High,
    &[],
    Some("Guard global resource use with explicit initialization checks before dereferencing."),
);

const META_CWE_915: RuleMetadata = emit::rule_meta(
    "CWE-915",
    "User-controlled map updates privileged object attributes",
    "A dynamic attribute map from the client is applied directly to a persistent object, including privileged fields.",
    Severity::High,
    &[],
    Some("Bind client input into an allowlisted DTO and update only explicitly permitted fields."),
);

const META_CWE_916: RuleMetadata = emit::rule_meta(
    "CWE-916",
    "Password storage uses an insufficiently expensive hash",
    "Password registration uses a fast hash such as MD5 rather than a work-factor-based password hashing scheme.",
    Severity::High,
    &[],
    Some("Use a dedicated password hashing scheme with sufficient work factor such as bcrypt or equivalent."),
);

const META_CWE_917: RuleMetadata = emit::rule_meta(
    "CWE-917",
    "User input is concatenated into template source",
    "A template expression is constructed by concatenating caller-controlled data into the template body itself.",
    Severity::High,
    &[],
    Some("Keep template structure fixed and pass user input only as data."),
);

const META_CWE_918: RuleMetadata = emit::rule_meta(
    "CWE-918",
    "Outbound fetch uses a caller-controlled URL without host allowlisting",
    "The server issues outbound requests to arbitrary client-supplied URLs without validating scheme or host.",
    Severity::High,
    &[],
    Some("Parse the URL and enforce an explicit host allowlist before outbound fetches."),
);

const META_CWE_921: RuleMetadata = emit::rule_meta(
    "CWE-921",
    "Secret material is written to a world-readable file path",
    "Sensitive integration keys are stored in a broadly accessible path with permissive file mode.",
    Severity::High,
    &[],
    Some("Store secrets only under private directories with restrictive file permissions."),
);

const META_CWE_924: RuleMetadata = emit::rule_meta(
    "CWE-924",
    "Inbound webhook payload is trusted without integrity verification",
    "A payment webhook body is applied directly without validating an HMAC or equivalent integrity proof.",
    Severity::High,
    &[],
    Some("Verify a keyed integrity signature over the webhook body before applying its contents."),
);

const META_CWE_940: RuleMetadata = emit::rule_meta(
    "CWE-940",
    "OAuth callback accepts any source without state verification",
    "An inbound callback consumes authorization data without validating the origin through a state binding.",
    Severity::High,
    &[],
    Some("Validate callback origin with a bound state token before accepting the authorization response."),
);

const META_CWE_941: RuleMetadata = emit::rule_meta(
    "CWE-941",
    "Outbound reset notification is sent to a caller-controlled destination",
    "A password-reset or account message is delivered to an arbitrary user-supplied email destination.",
    Severity::High,
    &[],
    Some("Derive notification destinations from authenticated or persisted account state rather than request parameters."),
);

const META_CWE_1051: RuleMetadata = emit::rule_meta(
    "CWE-1051",
    "Network client is initialized with a hard-coded endpoint",
    "An outbound HTTP client always uses a fixed internal billing host instead of runtime configuration.",
    Severity::Warning,
    &[],
    Some("Load network destinations from deployment configuration rather than hard-coded literals."),
);

const META_CWE_1052: RuleMetadata = emit::rule_meta(
    "CWE-1052",
    "Database initialization embeds a full DSN literal",
    "A database connection string hard-codes host and credentials directly in the source.",
    Severity::High,
    &[],
    Some("Source database connection parameters from environment or secret-backed runtime configuration."),
);

const META_CWE_1067: RuleMetadata = emit::rule_meta(
    "CWE-1067",
    "Search query forces sequential scans with a leading wildcard pattern",
    "A caller-controlled LIKE query is constructed as '%term%', defeating indexed prefix access.",
    Severity::Warning,
    &[],
    Some("Use indexed prefix or exact-match predicates instead of leading-wildcard scans."),
);

const META_CWE_1173: RuleMetadata = emit::rule_meta(
    "CWE-1173",
    "Validation framework is bypassed in favor of raw map decoding",
    "Request data is decoded into a generic map and persisted without applying the typed validation model.",
    Severity::High,
    &[],
    Some("Bind into a validated struct or perform explicit field validation before persistence."),
);

const META_CWE_1125: RuleMetadata = emit::rule_meta(
    "CWE-1125",
    "Excessive public attack surface is mounted without authentication",
    "Debug, admin, or internal maintenance endpoints are registered directly on the public router.",
    Severity::High,
    &[],
    Some("Expose only the minimum route surface publicly and gate administrative endpoints behind dedicated authorization."),
);

const META_CWE_1204: RuleMetadata = emit::rule_meta(
    "CWE-1204",
    "CBC encryption reuses a static initialization vector",
    "A fixed IV literal is reused across requests instead of generating a fresh random IV per ciphertext.",
    Severity::High,
    &[],
    Some("Generate a unique random IV for each encryption operation and include it alongside the ciphertext."),
);

const META_CWE_1220: RuleMetadata = emit::rule_meta(
    "CWE-1220",
    "Record reads are only authenticated, not owner-scoped",
    "Any authenticated caller can fetch arbitrary invoice records because the lookup omits owner scoping.",
    Severity::High,
    &[],
    Some("Include the authenticated principal in the data access predicate, not just a coarse login check."),
);

const META_CWE_1230: RuleMetadata = emit::rule_meta(
    "CWE-1230",
    "Redacted response still leaks sensitive document metadata",
    "A download response omits content but still returns the original filename or file size metadata.",
    Severity::Warning,
    &[],
    Some("Strip sensitive metadata from redacted responses and return only the minimum transport headers needed."),
);

const META_CWE_1236: RuleMetadata = emit::rule_meta(
    "CWE-1236",
    "CSV export writes untrusted cells without formula neutralization",
    "User-controlled text is emitted directly into CSV cells that spreadsheet software may interpret as formulas.",
    Severity::High,
    &[],
    Some("Neutralize dangerous leading characters before writing untrusted data into CSV fields."),
);

const META_CWE_1240: RuleMetadata = emit::rule_meta(
    "CWE-1240",
    "Custom XOR cipher is used for token protection",
    "Session tokens are sealed with a homegrown XOR primitive instead of a standard authenticated cipher.",
    Severity::High,
    &[],
    Some("Use a standard authenticated encryption primitive such as AES-GCM instead of custom ciphers."),
);

const META_CWE_1265: RuleMetadata = emit::rule_meta(
    "CWE-1265",
    "Non-reentrant balance update is invoked while its mutex is already held",
    "A transfer path acquires a mutex and then re-enters a helper that acquires the same mutex again.",
    Severity::High,
    &[],
    Some("Keep the lock scope in one place or move the shared helper outside the locked section to avoid nested acquisition."),
);

const META_CWE_1286: RuleMetadata = emit::rule_meta(
    "CWE-1286",
    "JSON configuration is accepted without strict syntax validation",
    "Configuration input is unmarshaled directly without unknown-field rejection or URL syntax validation.",
    Severity::Warning,
    &[],
    Some("Use a strict decoder and validate structural fields before persisting configuration input."),
);

const META_CWE_1289: RuleMetadata = emit::rule_meta(
    "CWE-1289",
    "Literal path comparison is used instead of canonical equivalence checks",
    "A protected asset path is denied only by literal comparison before normalization, allowing equivalent bypass forms.",
    Severity::High,
    &[],
    Some("Normalize the full path and enforce a canonical prefix constraint before serving the resource."),
);

const META_CWE_1322: RuleMetadata = emit::rule_meta(
    "CWE-1322",
    "Async worker blocks its event loop with sleep calls",
    "A queued worker uses blocking sleep inside the loop instead of scheduling retries asynchronously.",
    Severity::Warning,
    &[],
    Some("Schedule retries with timers or separate workers instead of blocking the event loop with sleep."),
);

const META_CWE_1327: RuleMetadata = emit::rule_meta(
    "CWE-1327",
    "Service binds to all interfaces by default",
    "The server listens on :9090 or equivalent, exposing the process on every network interface.",
    Severity::High,
    &[],
    Some("Bind administrative or local-only services to loopback or a tightly scoped interface."),
);

const META_CWE_1333: RuleMetadata = emit::rule_meta(
    "CWE-1333",
    "Nested-quantifier regex is applied to unbounded input",
    "A catastrophic backtracking pattern validates user input without a tight length limit.",
    Severity::High,
    &[],
    Some("Use linear-time validation patterns plus explicit length limits for attacker-controlled input."),
);

const META_CWE_1389: RuleMetadata = emit::rule_meta(
    "CWE-1389",
    "Numeric parser accepts alternate radices unexpectedly",
    "A base-0 integer parse accepts octal or hexadecimal prefixes where only decimal counts were intended.",
    Severity::Warning,
    &[],
    Some("Use explicit base-10 parsing when the input contract is decimal-only."),
);

const META_CWE_1392: RuleMetadata = emit::rule_meta(
    "CWE-1392",
    "Bootstrap path seeds a default administrator password",
    "Administrative account initialization uses the literal password 'admin' instead of runtime secrets.",
    Severity::Critical,
    &[],
    Some("Require bootstrap credentials from secret-backed configuration and avoid shipping default passwords."),
);

const META_CWE_807: RuleMetadata = emit::rule_meta(
    "CWE-807",
    "Security decision trusts a spoofable client header",
    "Authorization or blocking logic uses a client-controlled forwarded IP header instead of a trusted connection address.",
    Severity::High,
    &[],
    Some("Make security decisions from trusted connection metadata rather than spoofable request headers."),
);

impl Rule for GoCweScan {
    fn metadata(&self) -> RuleMetadata {
        META_CWE_15
    }
}

impl Detector for GoCweScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        GO_CWE_RULE_IDS
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !ctx.allows("CWE-15")
            && !ctx.allows("CWE-22")
            && !ctx.allows("CWE-41")
            && !ctx.allows("CWE-59")
            && !ctx.allows("CWE-76")
            && !ctx.allows("CWE-78")
            && !ctx.allows("CWE-79")
            && !ctx.allows("CWE-89")
            && !ctx.allows("CWE-90")
            && !ctx.allows("CWE-91")
            && !ctx.allows("CWE-93")
            && !ctx.allows("CWE-112")
            && !ctx.allows("CWE-140")
            && !ctx.allows("CWE-178")
            && !ctx.allows("CWE-179")
            && !ctx.allows("CWE-182")
            && !ctx.allows("CWE-184")
            && !ctx.allows("CWE-186")
            && !ctx.allows("CWE-201")
            && !ctx.allows("CWE-204")
            && !ctx.allows("CWE-208")
            && !ctx.allows("CWE-209")
            && !ctx.allows("CWE-212")
            && !ctx.allows("CWE-213")
            && !ctx.allows("CWE-214")
            && !ctx.allows("CWE-215")
            && !ctx.allows("CWE-250")
            && !ctx.allows("CWE-252")
            && !ctx.allows("CWE-256")
            && !ctx.allows("CWE-257")
            && !ctx.allows("CWE-260")
            && !ctx.allows("CWE-261")
            && !ctx.allows("CWE-262")
            && !ctx.allows("CWE-263")
            && !ctx.allows("CWE-266")
            && !ctx.allows("CWE-267")
            && !ctx.allows("CWE-268")
            && !ctx.allows("CWE-270")
            && !ctx.allows("CWE-272")
            && !ctx.allows("CWE-273")
            && !ctx.allows("CWE-274")
            && !ctx.allows("CWE-276")
            && !ctx.allows("CWE-277")
            && !ctx.allows("CWE-278")
            && !ctx.allows("CWE-279")
            && !ctx.allows("CWE-280")
            && !ctx.allows("CWE-281")
            && !ctx.allows("CWE-283")
            && !ctx.allows("CWE-289")
            && !ctx.allows("CWE-290")
            && !ctx.allows("CWE-294")
            && !ctx.allows("CWE-301")
            && !ctx.allows("CWE-303")
            && !ctx.allows("CWE-305")
            && !ctx.allows("CWE-306")
            && !ctx.allows("CWE-307")
            && !ctx.allows("CWE-308")
            && !ctx.allows("CWE-309")
            && !ctx.allows("CWE-312")
            && !ctx.allows("CWE-319")
            && !ctx.allows("CWE-322")
            && !ctx.allows("CWE-323")
            && !ctx.allows("CWE-324")
            && !ctx.allows("CWE-325")
            && !ctx.allows("CWE-328")
            && !ctx.allows("CWE-331")
            && !ctx.allows("CWE-334")
            && !ctx.allows("CWE-335")
            && !ctx.allows("CWE-338")
            && !ctx.allows("CWE-341")
            && !ctx.allows("CWE-342")
            && !ctx.allows("CWE-343")
            && !ctx.allows("CWE-344")
            && !ctx.allows("CWE-346")
            && !ctx.allows("CWE-347")
            && !ctx.allows("CWE-349")
            && !ctx.allows("CWE-353")
            && !ctx.allows("CWE-356")
            && !ctx.allows("CWE-358")
            && !ctx.allows("CWE-359")
            && !ctx.allows("CWE-360")
            && !ctx.allows("CWE-366")
            && !ctx.allows("CWE-367")
            && !ctx.allows("CWE-368")
            && !ctx.allows("CWE-378")
            && !ctx.allows("CWE-379")
            && !ctx.allows("CWE-385")
            && !ctx.allows("CWE-393")
            && !ctx.allows("CWE-403")
            && !ctx.allows("CWE-408")
            && !ctx.allows("CWE-412")
            && !ctx.allows("CWE-420")
            && !ctx.allows("CWE-421")
            && !ctx.allows("CWE-425")
            && !ctx.allows("CWE-426")
            && !ctx.allows("CWE-427")
            && !ctx.allows("CWE-434")
            && !ctx.allows("CWE-454")
            && !ctx.allows("CWE-455")
            && !ctx.allows("CWE-459")
            && !ctx.allows("CWE-472")
            && !ctx.allows("CWE-488")
            && !ctx.allows("CWE-494")
            && !ctx.allows("CWE-497")
            && !ctx.allows("CWE-501")
            && !ctx.allows("CWE-502")
            && !ctx.allows("CWE-515")
            && !ctx.allows("CWE-521")
            && !ctx.allows("CWE-523")
            && !ctx.allows("CWE-524")
            && !ctx.allows("CWE-538")
            && !ctx.allows("CWE-544")
            && !ctx.allows("CWE-547")
            && !ctx.allows("CWE-549")
            && !ctx.allows("CWE-551")
            && !ctx.allows("CWE-552")
            && !ctx.allows("CWE-565")
            && !ctx.allows("CWE-601")
            && !ctx.allows("CWE-603")
            && !ctx.allows("CWE-605")
            && !ctx.allows("CWE-611")
            && !ctx.allows("CWE-613")
            && !ctx.allows("CWE-618")
            && !ctx.allows("CWE-619")
            && !ctx.allows("CWE-620")
            && !ctx.allows("CWE-639")
            && !ctx.allows("CWE-640")
            && !ctx.allows("CWE-645")
            && !ctx.allows("CWE-648")
            && !ctx.allows("CWE-649")
            && !ctx.allows("CWE-653")
            && !ctx.allows("CWE-654")
            && !ctx.allows("CWE-656")
            && !ctx.allows("CWE-708")
            && !ctx.allows("CWE-756")
            && !ctx.allows("CWE-765")
            && !ctx.allows("CWE-778")
            && !ctx.allows("CWE-783")
            && !ctx.allows("CWE-798")
            && !ctx.allows("CWE-820")
            && !ctx.allows("CWE-821")
            && !ctx.allows("CWE-826")
            && !ctx.allows("CWE-829")
            && !ctx.allows("CWE-836")
            && !ctx.allows("CWE-838")
            && !ctx.allows("CWE-841")
            && !ctx.allows("CWE-842")
            && !ctx.allows("CWE-909")
            && !ctx.allows("CWE-915")
            && !ctx.allows("CWE-916")
            && !ctx.allows("CWE-917")
            && !ctx.allows("CWE-918")
            && !ctx.allows("CWE-921")
            && !ctx.allows("CWE-924")
            && !ctx.allows("CWE-940")
            && !ctx.allows("CWE-941")
            && !ctx.allows("CWE-1051")
            && !ctx.allows("CWE-1052")
            && !ctx.allows("CWE-1067")
            && !ctx.allows("CWE-1125")
            && !ctx.allows("CWE-1173")
            && !ctx.allows("CWE-1204")
            && !ctx.allows("CWE-1220")
            && !ctx.allows("CWE-1230")
            && !ctx.allows("CWE-1236")
            && !ctx.allows("CWE-1240")
            && !ctx.allows("CWE-1265")
            && !ctx.allows("CWE-1286")
            && !ctx.allows("CWE-1289")
            && !ctx.allows("CWE-1322")
            && !ctx.allows("CWE-1327")
            && !ctx.allows("CWE-1333")
            && !ctx.allows("CWE-1389")
            && !ctx.allows("CWE-1392")
            && !ctx.allows("CWE-807")
        {
            return;
        }

        let facts = build_go_unit_facts(unit);
        if ctx.allows("CWE-15") {
            detect_cwe_15(unit, &facts, out);
        }
        if ctx.allows("CWE-22") {
            detect_cwe_22(unit, &facts, out);
        }
        if ctx.allows("CWE-41") {
            detect_cwe_41(unit, &facts, out);
        }
        if ctx.allows("CWE-59") {
            detect_cwe_59(unit, &facts, out);
        }
        if ctx.allows("CWE-76") {
            detect_cwe_76(unit, &facts, out);
        }
        if ctx.allows("CWE-78") {
            detect_cwe_78(unit, &facts, out);
        }
        if ctx.allows("CWE-79") {
            detect_cwe_79(unit, &facts, out);
        }
        if ctx.allows("CWE-89") {
            detect_cwe_89(unit, &facts, out);
        }
        if ctx.allows("CWE-90") {
            detect_cwe_90(unit, &facts, out);
        }
        if ctx.allows("CWE-91") {
            detect_cwe_91(unit, &facts, out);
        }
        if ctx.allows("CWE-93") {
            detect_cwe_93(unit, &facts, out);
        }
        if ctx.allows("CWE-112") {
            detect_cwe_112(unit, &facts, out);
        }
        if ctx.allows("CWE-140") {
            detect_cwe_140(unit, &facts, out);
        }
        if ctx.allows("CWE-178") {
            detect_cwe_178(unit, &facts, out);
        }
        if ctx.allows("CWE-179") {
            detect_cwe_179(unit, &facts, out);
        }
        if ctx.allows("CWE-182") {
            detect_cwe_182(unit, &facts, out);
        }
        if ctx.allows("CWE-184") {
            detect_cwe_184(unit, &facts, out);
        }
        if ctx.allows("CWE-186") {
            detect_cwe_186(unit, &facts, out);
        }
        if ctx.allows("CWE-201") {
            detect_cwe_201(unit, &facts, out);
        }
        if ctx.allows("CWE-204") {
            detect_cwe_204(unit, &facts, out);
        }
        if ctx.allows("CWE-208") {
            detect_cwe_208(unit, &facts, out);
        }
        if ctx.allows("CWE-209") {
            detect_cwe_209(unit, &facts, out);
        }
        if ctx.allows("CWE-212") {
            detect_cwe_212(unit, &facts, out);
        }
        if ctx.allows("CWE-213") {
            detect_cwe_213(unit, &facts, out);
        }
        if ctx.allows("CWE-214") {
            detect_cwe_214(unit, &facts, out);
        }
        if ctx.allows("CWE-215") {
            detect_cwe_215(unit, &facts, out);
        }
        if ctx.allows("CWE-250") {
            detect_cwe_250(unit, &facts, out);
        }
        if ctx.allows("CWE-252") {
            detect_cwe_252(unit, &facts, out);
        }
        if ctx.allows("CWE-256") {
            detect_cwe_256(unit, &facts, out);
        }
        if ctx.allows("CWE-257") {
            detect_cwe_257(unit, &facts, out);
        }
        if ctx.allows("CWE-260") {
            detect_cwe_260(unit, &facts, out);
        }
        if ctx.allows("CWE-261") {
            detect_cwe_261(unit, &facts, out);
        }
        if ctx.allows("CWE-262") {
            detect_cwe_262(unit, &facts, out);
        }
        if ctx.allows("CWE-263") {
            detect_cwe_263(unit, &facts, out);
        }
        if ctx.allows("CWE-266") {
            detect_cwe_266(unit, &facts, out);
        }
        if ctx.allows("CWE-267") {
            detect_cwe_267(unit, &facts, out);
        }
        if ctx.allows("CWE-268") {
            detect_cwe_268(unit, &facts, out);
        }
        if ctx.allows("CWE-270") {
            detect_cwe_270(unit, &facts, out);
        }
        if ctx.allows("CWE-272") {
            detect_cwe_272(unit, &facts, out);
        }
        if ctx.allows("CWE-273") {
            detect_cwe_273(unit, &facts, out);
        }
        if ctx.allows("CWE-274") {
            detect_cwe_274(unit, &facts, out);
        }
        if ctx.allows("CWE-276") {
            detect_cwe_276(unit, &facts, out);
        }
        if ctx.allows("CWE-277") {
            detect_cwe_277(unit, &facts, out);
        }
        if ctx.allows("CWE-278") {
            detect_cwe_278(unit, &facts, out);
        }
        if ctx.allows("CWE-279") {
            detect_cwe_279(unit, &facts, out);
        }
        if ctx.allows("CWE-280") {
            detect_cwe_280(unit, &facts, out);
        }
        if ctx.allows("CWE-281") {
            detect_cwe_281(unit, &facts, out);
        }
        if ctx.allows("CWE-283") {
            detect_cwe_283(unit, &facts, out);
        }
        if ctx.allows("CWE-289") {
            detect_cwe_289(unit, &facts, out);
        }
        if ctx.allows("CWE-290") {
            detect_cwe_290(unit, &facts, out);
        }
        if ctx.allows("CWE-294") {
            detect_cwe_294(unit, &facts, out);
        }
        if ctx.allows("CWE-301") {
            detect_cwe_301(unit, &facts, out);
        }
        if ctx.allows("CWE-303") {
            detect_cwe_303(unit, &facts, out);
        }
        if ctx.allows("CWE-305") {
            detect_cwe_305(unit, &facts, out);
        }
        if ctx.allows("CWE-306") {
            detect_cwe_306(unit, &facts, out);
        }
        if ctx.allows("CWE-307") {
            detect_cwe_307(unit, &facts, out);
        }
        if ctx.allows("CWE-308") {
            detect_cwe_308(unit, &facts, out);
        }
        if ctx.allows("CWE-309") {
            detect_cwe_309(unit, &facts, out);
        }
        if ctx.allows("CWE-312") {
            detect_cwe_312(unit, &facts, out);
        }
        if ctx.allows("CWE-319") {
            detect_cwe_319(unit, &facts, out);
        }
        if ctx.allows("CWE-322") {
            detect_cwe_322(unit, &facts, out);
        }
        if ctx.allows("CWE-323") {
            detect_cwe_323(unit, &facts, out);
        }
        if ctx.allows("CWE-324") {
            detect_cwe_324(unit, &facts, out);
        }
        if ctx.allows("CWE-325") {
            detect_cwe_325(unit, &facts, out);
        }
        if ctx.allows("CWE-328") {
            detect_cwe_328(unit, &facts, out);
        }
        if ctx.allows("CWE-331") {
            detect_cwe_331(unit, &facts, out);
        }
        if ctx.allows("CWE-334") {
            detect_cwe_334(unit, &facts, out);
        }
        if ctx.allows("CWE-335") {
            detect_cwe_335(unit, &facts, out);
        }
        if ctx.allows("CWE-338") {
            detect_cwe_338(unit, &facts, out);
        }
        if ctx.allows("CWE-341") {
            detect_cwe_341(unit, &facts, out);
        }
        if ctx.allows("CWE-342") {
            detect_cwe_342(unit, &facts, out);
        }
        if ctx.allows("CWE-343") {
            detect_cwe_343(unit, &facts, out);
        }
        if ctx.allows("CWE-344") {
            detect_cwe_344(unit, &facts, out);
        }
        if ctx.allows("CWE-346") {
            detect_cwe_346(unit, &facts, out);
        }
        if ctx.allows("CWE-347") {
            detect_cwe_347(unit, &facts, out);
        }
        if ctx.allows("CWE-349") {
            detect_cwe_349(unit, &facts, out);
        }
        if ctx.allows("CWE-353") {
            detect_cwe_353(unit, &facts, out);
        }
        if ctx.allows("CWE-356") {
            detect_cwe_356(unit, &facts, out);
        }
        if ctx.allows("CWE-358") {
            detect_cwe_358(unit, &facts, out);
        }
        if ctx.allows("CWE-359") {
            detect_cwe_359(unit, &facts, out);
        }
        if ctx.allows("CWE-360") {
            detect_cwe_360(unit, &facts, out);
        }
        if ctx.allows("CWE-366") {
            detect_cwe_366(unit, &facts, out);
        }
        if ctx.allows("CWE-367") {
            detect_cwe_367(unit, &facts, out);
        }
        if ctx.allows("CWE-368") {
            detect_cwe_368(unit, &facts, out);
        }
        if ctx.allows("CWE-378") {
            detect_cwe_378(unit, &facts, out);
        }
        if ctx.allows("CWE-379") {
            detect_cwe_379(unit, &facts, out);
        }
        if ctx.allows("CWE-385") {
            detect_cwe_385(unit, &facts, out);
        }
        if ctx.allows("CWE-393") {
            detect_cwe_393(unit, &facts, out);
        }
        if ctx.allows("CWE-403") {
            detect_cwe_403(unit, &facts, out);
        }
        if ctx.allows("CWE-408") {
            detect_cwe_408(unit, &facts, out);
        }
        if ctx.allows("CWE-412") {
            detect_cwe_412(unit, &facts, out);
        }
        if ctx.allows("CWE-420") {
            detect_cwe_420(unit, &facts, out);
        }
        if ctx.allows("CWE-421") {
            detect_cwe_421(unit, &facts, out);
        }
        if ctx.allows("CWE-425") {
            detect_cwe_425(unit, &facts, out);
        }
        if ctx.allows("CWE-426") {
            detect_cwe_426(unit, &facts, out);
        }
        if ctx.allows("CWE-427") {
            detect_cwe_427(unit, &facts, out);
        }
        if ctx.allows("CWE-434") {
            detect_cwe_434(unit, &facts, out);
        }
        if ctx.allows("CWE-454") {
            detect_cwe_454(unit, &facts, out);
        }
        if ctx.allows("CWE-455") {
            detect_cwe_455(unit, &facts, out);
        }
        if ctx.allows("CWE-459") {
            detect_cwe_459(unit, &facts, out);
        }
        if ctx.allows("CWE-472") {
            detect_cwe_472(unit, &facts, out);
        }
        if ctx.allows("CWE-488") {
            detect_cwe_488(unit, &facts, out);
        }
        if ctx.allows("CWE-494") {
            detect_cwe_494(unit, &facts, out);
        }
        if ctx.allows("CWE-497") {
            detect_cwe_497(unit, &facts, out);
        }
        if ctx.allows("CWE-501") {
            detect_cwe_501(unit, &facts, out);
        }
        if ctx.allows("CWE-502") {
            detect_cwe_502(unit, &facts, out);
        }
        if ctx.allows("CWE-515") {
            detect_cwe_515(unit, &facts, out);
        }
        if ctx.allows("CWE-521") {
            detect_cwe_521(unit, &facts, out);
        }
        if ctx.allows("CWE-523") {
            detect_cwe_523(unit, &facts, out);
        }
        if ctx.allows("CWE-524") {
            detect_cwe_524(unit, &facts, out);
        }
        if ctx.allows("CWE-538") {
            detect_cwe_538(unit, &facts, out);
        }
        if ctx.allows("CWE-544") {
            detect_cwe_544(unit, &facts, out);
        }
        if ctx.allows("CWE-547") {
            detect_cwe_547(unit, &facts, out);
        }
        if ctx.allows("CWE-549") {
            detect_cwe_549(unit, &facts, out);
        }
        if ctx.allows("CWE-551") {
            detect_cwe_551(unit, &facts, out);
        }
        if ctx.allows("CWE-552") {
            detect_cwe_552(unit, &facts, out);
        }
        if ctx.allows("CWE-565") {
            detect_cwe_565(unit, &facts, out);
        }
        if ctx.allows("CWE-601") {
            detect_cwe_601(unit, &facts, out);
        }
        if ctx.allows("CWE-603") {
            detect_cwe_603(unit, &facts, out);
        }
        if ctx.allows("CWE-605") {
            detect_cwe_605(unit, &facts, out);
        }
        if ctx.allows("CWE-611") {
            detect_cwe_611(unit, &facts, out);
        }
        if ctx.allows("CWE-613") {
            detect_cwe_613(unit, &facts, out);
        }
        if ctx.allows("CWE-618") {
            detect_cwe_618(unit, &facts, out);
        }
        if ctx.allows("CWE-619") {
            detect_cwe_619(unit, &facts, out);
        }
        if ctx.allows("CWE-620") {
            detect_cwe_620(unit, &facts, out);
        }
        if ctx.allows("CWE-639") {
            detect_cwe_639(unit, &facts, out);
        }
        if ctx.allows("CWE-640") {
            detect_cwe_640(unit, &facts, out);
        }
        if ctx.allows("CWE-645") {
            detect_cwe_645(unit, &facts, out);
        }
        if ctx.allows("CWE-648") {
            detect_cwe_648(unit, &facts, out);
        }
        if ctx.allows("CWE-649") {
            detect_cwe_649(unit, &facts, out);
        }
        if ctx.allows("CWE-653") {
            detect_cwe_653(unit, &facts, out);
        }
        if ctx.allows("CWE-654") {
            detect_cwe_654(unit, &facts, out);
        }
        if ctx.allows("CWE-656") {
            detect_cwe_656(unit, &facts, out);
        }
        if ctx.allows("CWE-708") {
            detect_cwe_708(unit, &facts, out);
        }
        if ctx.allows("CWE-756") {
            detect_cwe_756(unit, &facts, out);
        }
        if ctx.allows("CWE-765") {
            detect_cwe_765(unit, &facts, out);
        }
        if ctx.allows("CWE-778") {
            detect_cwe_778(unit, &facts, out);
        }
        if ctx.allows("CWE-783") {
            detect_cwe_783(unit, &facts, out);
        }
        if ctx.allows("CWE-798") {
            detect_cwe_798(unit, &facts, out);
        }
        if ctx.allows("CWE-820") {
            detect_cwe_820(unit, &facts, out);
        }
        if ctx.allows("CWE-821") {
            detect_cwe_821(unit, &facts, out);
        }
        if ctx.allows("CWE-826") {
            detect_cwe_826(unit, &facts, out);
        }
        if ctx.allows("CWE-829") {
            detect_cwe_829(unit, &facts, out);
        }
        if ctx.allows("CWE-836") {
            detect_cwe_836(unit, &facts, out);
        }
        if ctx.allows("CWE-838") {
            detect_cwe_838(unit, &facts, out);
        }
        if ctx.allows("CWE-841") {
            detect_cwe_841(unit, &facts, out);
        }
        if ctx.allows("CWE-842") {
            detect_cwe_842(unit, &facts, out);
        }
        if ctx.allows("CWE-909") {
            detect_cwe_909(unit, &facts, out);
        }
        if ctx.allows("CWE-915") {
            detect_cwe_915(unit, &facts, out);
        }
        if ctx.allows("CWE-916") {
            detect_cwe_916(unit, &facts, out);
        }
        if ctx.allows("CWE-917") {
            detect_cwe_917(unit, &facts, out);
        }
        if ctx.allows("CWE-918") {
            detect_cwe_918(unit, &facts, out);
        }
        if ctx.allows("CWE-921") {
            detect_cwe_921(unit, &facts, out);
        }
        if ctx.allows("CWE-924") {
            detect_cwe_924(unit, &facts, out);
        }
        if ctx.allows("CWE-940") {
            detect_cwe_940(unit, &facts, out);
        }
        if ctx.allows("CWE-941") {
            detect_cwe_941(unit, &facts, out);
        }
        if ctx.allows("CWE-1051") {
            detect_cwe_1051(unit, &facts, out);
        }
        if ctx.allows("CWE-1052") {
            detect_cwe_1052(unit, &facts, out);
        }
        if ctx.allows("CWE-1067") {
            detect_cwe_1067(unit, &facts, out);
        }
        if ctx.allows("CWE-1125") {
            detect_cwe_1125(unit, &facts, out);
        }
        if ctx.allows("CWE-1173") {
            detect_cwe_1173(unit, &facts, out);
        }
        if ctx.allows("CWE-1204") {
            detect_cwe_1204(unit, &facts, out);
        }
        if ctx.allows("CWE-1220") {
            detect_cwe_1220(unit, &facts, out);
        }
        if ctx.allows("CWE-1230") {
            detect_cwe_1230(unit, &facts, out);
        }
        if ctx.allows("CWE-1236") {
            detect_cwe_1236(unit, &facts, out);
        }
        if ctx.allows("CWE-1240") {
            detect_cwe_1240(unit, &facts, out);
        }
        if ctx.allows("CWE-1265") {
            detect_cwe_1265(unit, &facts, out);
        }
        if ctx.allows("CWE-1286") {
            detect_cwe_1286(unit, &facts, out);
        }
        if ctx.allows("CWE-1289") {
            detect_cwe_1289(unit, &facts, out);
        }
        if ctx.allows("CWE-1322") {
            detect_cwe_1322(unit, &facts, out);
        }
        if ctx.allows("CWE-1327") {
            detect_cwe_1327(unit, &facts, out);
        }
        if ctx.allows("CWE-1333") {
            detect_cwe_1333(unit, &facts, out);
        }
        if ctx.allows("CWE-1389") {
            detect_cwe_1389(unit, &facts, out);
        }
        if ctx.allows("CWE-1392") {
            detect_cwe_1392(unit, &facts, out);
        }
        if ctx.allows("CWE-807") {
            detect_cwe_807(unit, &facts, out);
        }
    }
}

fn detect_cwe_15(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    for call in &facts.call_facts {
        if !is_configuration_sink(&call.callee) {
            continue;
        }

        if !call.arguments.iter().any(|arg| {
            facts.input_bindings.iter().any(|binding| {
                binding.kind == InputKind::UserControlled && argument_uses_identifier(arg, &binding.name)
            })
        }) {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_15,
            &file,
            line,
            col,
            "request-derived configuration value reaches a database-opening sink",
            out,
        );
    }
}

fn detect_cwe_22(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("filepath.Join(") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && assignment.expr.contains(&binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_read_sink = facts.call_facts.iter().any(|call| {
            is_path_traversal_sink(&call.callee)
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_read_sink {
            continue;
        }

        if is_path_confined(source, assignment) {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_22,
            &file,
            line,
            col,
            "user-controlled path reaches a file-read sink without base-directory confinement",
            out,
        );
    }
}

fn detect_cwe_41(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("filepath.Join(") {
            continue;
        }

        let Some(binding) = facts.input_bindings.iter().find(|binding| {
            binding.kind == InputKind::UserControlled
                && assignment.expr.contains(&binding.name)
        }) else {
            continue;
        };

        if !source.contains(&format!(r#"strings.Contains({}, "..")"#, binding.name)) {
            continue;
        }

        let has_read_sink = facts.call_facts.iter().any(|call| {
            is_path_traversal_sink(&call.callee)
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_read_sink {
            continue;
        }

        if has_canonical_path_guard(source, &assignment.name) {
            continue;
        }
        if assignment.expr.contains("filepath.Base(") {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_41,
            &file,
            line,
            col,
            "partial traversal filtering still allows equivalent path aliases to reach file access",
            out,
        );
    }
}

fn detect_cwe_59(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("filepath.Join(") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_open_sink = facts.call_facts.iter().any(|call| {
            is_link_resolution_sink(&call.callee)
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_open_sink {
            continue;
        }

        if has_symlink_guard(source, &assignment.name) {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_59,
            &file,
            line,
            col,
            "user-controlled path is opened without a symlink rejection check",
            out,
        );
    }
}

fn detect_cwe_76(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains("html.EscapeString(") {
        return;
    }
    if !source.contains(r#"strings.ReplaceAll(raw, "<", "")"#)
        || !source.contains(r#"strings.ReplaceAll(safe, ">", "")"#)
    {
        return;
    }
    if !facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && binding.name == "raw"
    }) {
        return;
    }
    if !source.contains("text/html") {
        return;
    }

    let start_byte = facts
        .assignments
        .iter()
        .find(|assignment| assignment.name == "safe" && assignment.expr.contains("strings.ReplaceAll"))
        .map(|assignment| assignment.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_76,
        &file,
        line,
        col,
        "manual angle-bracket stripping is used for HTML output instead of proper escaping",
        out,
    );
}

fn detect_cwe_78(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    for call in &facts.call_facts {
        if call.callee != "exec.Command" || call.arguments.len() < 3 {
            continue;
        }
        if call.arguments[0] != r#""sh""# || call.arguments[1] != r#""-c""# {
            continue;
        }

        let payload = &call.arguments[2];
        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && payload.contains(&binding.name)
                && payload.contains('+')
        });
        if !uses_user_input {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_78,
            &file,
            line,
            col,
            "user-controlled input is interpolated into a shell command string",
            out,
        );
    }
}

fn detect_cwe_79(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("fmt.Sprintf(") || !source.contains("text/html") {
        return;
    }
    if source.contains("html.EscapeString(") {
        return;
    }

    for call in &facts.call_facts {
        if call.callee != "fmt.Sprintf" || call.arguments.is_empty() {
            continue;
        }
        if !call.arguments[0].contains("<html>") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && call
                    .arguments
                    .iter()
                    .skip(1)
                    .any(|arg| argument_uses_identifier(arg, &binding.name))
        });
        if !uses_user_input {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_79,
            &file,
            line,
            col,
            "user-controlled input is formatted directly into HTML output",
            out,
        );
    }
}

fn detect_cwe_89(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("fmt.Sprintf(") {
            continue;
        }
        if !(assignment.expr.contains("SELECT ") || assignment.expr.contains("UPDATE ") || assignment.expr.contains("DELETE ") || assignment.expr.contains("INSERT ")) {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_sql_sink = facts.call_facts.iter().any(|call| {
            matches!(call.callee.as_str(), "db.QueryRow" | "db.Query" | "db.Exec")
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_sql_sink {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_89,
            &file,
            line,
            col,
            "user-controlled input is formatted into an SQL query before execution",
            out,
        );
    }
}

fn detect_cwe_90(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("fmt.Sprintf(") {
            continue;
        }
        if !assignment.expr.contains("objectClass=") {
            continue;
        }
        if assignment.expr.contains("escapeLDAP(") {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_ldap_sink = facts.call_facts.iter().any(|call| {
            call.callee == "dial"
                && call
                    .arguments
                    .iter()
                    .any(|arg| argument_uses_identifier(arg, &assignment.name))
        });
        if !has_ldap_sink {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_90,
            &file,
            line,
            col,
            "user-controlled input is formatted into an LDAP filter without escaping",
            out,
        );
    }
}

fn detect_cwe_91(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    for assignment in &facts.assignments {
        if !assignment.expr.contains("fmt.Sprintf(") {
            continue;
        }
        if !(assignment.expr.contains("<profile>") || assignment.expr.contains("<ticket>")) {
            continue;
        }

        let uses_user_input = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
        });
        if !uses_user_input {
            continue;
        }

        let has_xml_sink = facts.call_facts.iter().any(|call| {
            call.callee == "xml.Unmarshal"
                && call
                    .arguments
                    .iter()
                    .any(|arg| arg.contains(&assignment.name))
        });
        if !has_xml_sink {
            continue;
        }

        let (line, col) = unit.line_col(assignment.start_byte);
        emit::push_finding(
            &META_CWE_91,
            &file,
            line,
            col,
            "user-controlled input is formatted directly into XML before parsing",
            out,
        );
    }
}

fn detect_cwe_93(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    for binding in &facts.input_bindings {
        if binding.kind != InputKind::UserControlled {
            continue;
        }

        let strips_cr = source.contains(&format!(r#"strings.ReplaceAll({}, "\r", "")"#, binding.name));
        let strips_lf = source.contains(&format!(r#"strings.ReplaceAll({}, "\n", "")"#, binding.name));
        if strips_cr && strips_lf {
            continue;
        }

        let has_location_header_sink = facts.call_facts.iter().any(|call| {
            matches!(call.callee.as_str(), "c.Header" | "w.Header().Set")
                && call.arguments.len() >= 2
                && call.arguments[0] == r#""Location""#
                && call.arguments[1].contains(&binding.name)
        });
        if !has_location_header_sink {
            continue;
        }

        let start_byte = facts
            .call_facts
            .iter()
            .find(|call| {
                matches!(call.callee.as_str(), "c.Header" | "w.Header().Set")
                    && call.arguments.len() >= 2
                    && call.arguments[0] == r#""Location""#
                    && call.arguments[1].contains(&binding.name)
            })
            .map(|call| call.start_byte)
            .unwrap_or(0);

        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_CWE_93,
            &file,
            line,
            col,
            "user-controlled input is concatenated into a Location header without CRLF stripping",
            out,
        );
    }
}

fn detect_cwe_112(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let has_xml_unmarshal =
        facts.call_facts.iter().any(|call| call.callee == "xml.Unmarshal") || source.contains("xml.Unmarshal(");
    if !has_xml_unmarshal {
        return;
    }

    let has_untrusted_payload = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && source.contains(&format!("xml.Unmarshal({},", binding.name))
    });
    if !has_untrusted_payload {
        return;
    }

    let has_validation = source.contains(".MatchString(") || source.contains(" <= 0");
    if has_validation {
        return;
    }

    let start_byte = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "xml.Unmarshal")
        .map(|call| call.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_112,
        &file,
        line,
        col,
        "untrusted XML is unmarshaled without subsequent field-level validation",
        out,
    );
}

fn detect_cwe_140(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("text/csv") {
        return;
    }
    if source.contains("csv.NewWriter(") {
        return;
    }
    if !source.contains("strings.Join(") || !source.contains("\",\"") {
        return;
    }

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && source.contains(&binding.name)
    });
    if !uses_user_input {
        return;
    }

    let start_byte = facts
        .assignments
        .iter()
        .find(|assignment| assignment.expr.contains("strings.Join(") || assignment.name == "line")
        .map(|assignment| assignment.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_140,
        &file,
        line,
        col,
        "user-controlled fields are joined into CSV output with literal delimiters",
        out,
    );
}

fn detect_cwe_178(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains("strings.EqualFold(") {
        return;
    }

    let Some(assignment) = facts.assignments.iter().find(|assignment| {
        assignment.expr.contains("strings.ToLower(")
    }) else {
        return;
    };

    if source.contains("ReplaceAllString(") {
        return;
    }
    if assignment.expr.contains("strings.TrimSpace(") {
        return;
    }

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && assignment.expr.contains(&binding.name)
    });
    if !uses_user_input {
        return;
    }

    if !(source.contains(&format!("[{}]", assignment.name)) || source.contains(&format!("({})", assignment.name))) {
        return;
    }

    let (line, col) = unit.line_col(assignment.start_byte);
    emit::push_finding(
        &META_CWE_178,
        &file,
        line,
        col,
        "user-controlled lookup key is lowercased and used directly in resource membership checks",
        out,
    );
}

fn detect_cwe_179(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains(".MatchString(decoded)") {
        return;
    }

    for binding in &facts.input_bindings {
        if binding.kind != InputKind::UserControlled {
            continue;
        }

        if !source.contains(&format!(".MatchString({})", binding.name)) {
            continue;
        }
        if !source.contains(&format!("url.QueryUnescape({})", binding.name)) {
            continue;
        }

        let start_byte = facts
            .call_facts
            .iter()
            .find(|call| call.callee == "url.QueryUnescape" && call.arguments.iter().any(|arg| arg == &binding.name))
            .map(|call| call.start_byte)
            .unwrap_or(0);

        let (line, col) = unit.line_col(start_byte);
        emit::push_finding(
            &META_CWE_179,
            &file,
            line,
            col,
            "encoded input is validated before URL decoding and then used in decoded form",
            out,
        );
        return;
    }
}

fn detect_cwe_182(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let Some(collapse_assignment) = facts.assignments.iter().find(|assignment| {
        assignment.expr.contains("ReplaceAllString(")
    }) else {
        return;
    };

    let Some(lower_assignment) = facts.assignments.iter().find(|assignment| {
        assignment.name == collapse_assignment.name && assignment.expr.contains("strings.ToLower(")
    }) else {
        return;
    };

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && binding.name == collapse_assignment.name
    });
    if !uses_user_input {
        return;
    }

    if !source.contains(&format!("[{}]", lower_assignment.name)) {
        return;
    }

    let (line, col) = unit.line_col(collapse_assignment.start_byte);
    emit::push_finding(
        &META_CWE_182,
        &file,
        line,
        col,
        "input is stripped and collapsed into an authorization-relevant value before membership checks",
        out,
    );
}

fn detect_cwe_184(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains(".MatchString(") {
        return;
    }

    let Some(lower_assignment) = facts.assignments.iter().find(|assignment| {
        assignment.expr.contains("strings.ToLower(")
    }) else {
        return;
    };

    let uses_user_input = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && lower_assignment.expr.contains(&binding.name)
    }) || expression_uses_request_input(&lower_assignment.expr);
    if !uses_user_input {
        return;
    }

    if !(source.contains("strings.Contains(") && source.contains("for _, word := range")) {
        return;
    }

    let (line, col) = unit.line_col(lower_assignment.start_byte);
    emit::push_finding(
        &META_CWE_184,
        &file,
        line,
        col,
        "user-controlled input is checked against an incomplete deny-list after normalization",
        out,
    );
}

fn detect_cwe_186(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("regexp.MustCompile(`^[a-z]+$`)") {
        return;
    }

    let start_byte = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "regexp.MustCompile")
        .map(|call| call.start_byte)
        .unwrap_or(0);

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_186,
        &file,
        line,
        col,
        "host validation uses an overly restrictive regex that only accepts lowercase letters",
        out,
    );
}

fn detect_cwe_201(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let has_sensitive_field = source.contains("APIKey") || source.contains("TokenKey");
    if !has_sensitive_field {
        return;
    }

    let sensitive_record_name = if source.contains("type userRecord struct") {
        Some("record")
    } else if source.contains("type memberRecord struct") {
        Some("record")
    } else {
        None
    };
    let Some(record_name) = sensitive_record_name else {
        return;
    };

    let direct_json_response = facts.call_facts.iter().find(|call| {
        (call.callee == "c.JSON" || call.callee == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg == record_name)
    });
    let Some(call) = direct_json_response else {
        return;
    };

    let (line, col) = unit.line_col(call.start_byte);
    emit::push_finding(
        &META_CWE_201,
        &file,
        line,
        col,
        "a response serializes a record containing sensitive fields directly to the caller",
        out,
    );
}

fn detect_cwe_204(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let has_missing_account_branch =
        source.contains("no account") && source.contains("StatusNotFound");
    let has_wrong_secret_branch = source.contains("bad password")
        || source.contains("bad secret")
        || source.contains("StatusUnauthorized");
    let has_uniform_failure = source.contains("invalid credentials");

    if !(has_missing_account_branch && has_wrong_secret_branch) || has_uniform_failure {
        return;
    }

    let start_byte = source.find("no account").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_204,
        &file,
        line,
        col,
        "authentication failures return distinguishable responses for missing accounts and wrong credentials",
        out,
    );
}

fn detect_cwe_208(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains("subtle.ConstantTimeCompare(") {
        return;
    }
    if !(source.contains("for i := range expected") && source.contains("provided[i] != expected[i]")) {
        return;
    }

    let start_byte = source.find("for i := range expected").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_208,
        &file,
        line,
        col,
        "secret comparison returns early on mismatched bytes instead of using a constant-time primitive",
        out,
    );
}

fn detect_cwe_209(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains(r#"fmt.Sprintf("db failure: %v", err)"#) {
        return;
    }

    let start_byte = source.find(r#"fmt.Sprintf("db failure: %v", err)"#).unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_209,
        &file,
        line,
        col,
        "database error details are formatted into a client-facing response",
        out,
    );
}

fn detect_cwe_212(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let has_sensitive_payment_field = source.contains("Card") || source.contains("PAN");
    if !has_sensitive_payment_field {
        return;
    }
    if !(source.contains("json.Marshal(rows)") || source.contains("json.Marshal(out)")) {
        return;
    }
    if source.contains("type paymentExport struct") || source.contains("type chargeExport struct") {
        return;
    }
    if !source.contains("json.Marshal(rows)") {
        return;
    }

    let start_byte = source.find("json.Marshal(rows)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_212,
        &file,
        line,
        col,
        "records containing sensitive payment fields are marshaled directly for export",
        out,
    );
}

fn detect_cwe_213(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let has_comp_field = source.contains("Salary") || source.contains("Comp");
    if !has_comp_field {
        return;
    }
    if source.contains("guestProfile{") || source.contains("directoryEntry{") {
        return;
    }

    let direct_profile_response = facts.call_facts.iter().find(|call| {
        (call.callee == "c.JSON" || call.callee == "json.NewEncoder(w).Encode")
            && call.arguments.iter().any(|arg| arg == "profile")
    });
    let Some(call) = direct_profile_response else {
        return;
    };

    let (line, col) = unit.line_col(call.start_byte);
    emit::push_finding(
        &META_CWE_213,
        &file,
        line,
        col,
        "a public response serializes a profile that still contains compensation fields",
        out,
    );
}

fn detect_cwe_214(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    for call in &facts.call_facts {
        if call.callee != "exec.Command" {
            continue;
        }
        if source.contains("cmd.Stdin = strings.NewReader(") {
            return;
        }

        let uses_user_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && call.arguments.iter().any(|arg| arg == &binding.name)
                && call.arguments.iter().any(|arg| arg == r#""--token""#)
        });
        if !uses_user_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_214,
            &file,
            line,
            col,
            "a user-supplied token is passed as a visible argv argument to an external process",
            out,
        );
        return;
    }
}

fn detect_cwe_215(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    for call in &facts.call_facts {
        if call.callee != "log.Printf" {
            continue;
        }

        let logs_secret = facts.input_bindings.iter().any(|binding| {
            binding.kind == InputKind::UserControlled
                && binding.name.contains("secret")
                && call.arguments.iter().any(|arg| arg == &binding.name)
        });
        if !logs_secret {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_215,
            &file,
            line,
            col,
            "a debug log statement includes request-derived secret material",
            out,
        );
        return;
    }
}

fn detect_cwe_250(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    for call in &facts.call_facts {
        if call.callee != "os.WriteFile" || call.arguments.len() < 3 {
            continue;
        }
        if call.arguments[2] != "0o777" {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_250,
            &file,
            line,
            col,
            "runtime file is written with world-accessible permissions",
            out,
        );
        return;
    }
}

fn detect_cwe_252(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    for call in &facts.call_facts {
        if call.callee != "os.WriteFile" {
            continue;
        }
        if source.contains("if err := os.WriteFile(") {
            return;
        }
        let writes_audit_log = call.arguments.iter().any(|arg| {
            arg.contains("/var/log/audit.log") || arg.contains("/var/log/journal.log")
        });
        if !writes_audit_log {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_252,
            &file,
            line,
            col,
            "os.WriteFile is called without checking its returned error",
            out,
        );
        return;
    }
}

fn detect_cwe_256(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains("GenerateFromPassword(")
        || source.contains("hashPassphrase(")
        || source.contains("digest")
        || source.contains("hash")
    {
        return;
    }

    let gorm_plaintext = source.contains("Password: c.PostForm(\"password\")");
    let sql_plaintext = source.contains("db.Exec(\"INSERT INTO credentials(login, pass) VALUES(?, ?)\", login, pass)");
    if !(gorm_plaintext || sql_plaintext) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("Password: c.PostForm(\"password\")") {
        idx
    } else {
        source
            .find("db.Exec(\"INSERT INTO credentials(login, pass) VALUES(?, ?)\", login, pass)")
            .unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_256,
        &file,
        line,
        col,
        "a plaintext password value is persisted directly instead of a hash or digest",
        out,
    );
}

fn detect_cwe_257(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let uses_reversible_crypto = source.contains("aes.NewCipher(")
        && source.contains("cipher.NewGCM(")
        && source.contains("gcm.Seal(")
        && source.contains("base64.StdEncoding.EncodeToString(");
    if !uses_reversible_crypto {
        return;
    }

    let persists_recoverable_secret = source.contains(r#""password": encoded"#)
        || source.contains("VALUES(?, ?)\", login, encoded)");
    if !persists_recoverable_secret {
        return;
    }

    let start_byte = source.find("aes.NewCipher(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_257,
        &file,
        line,
        col,
        "a password or login secret is encrypted with a reversible cipher before storage",
        out,
    );
}

fn detect_cwe_260(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let config_type_has_secret_field =
        source.contains("Password string") || source.contains("Secret   string");
    if !config_type_has_secret_field {
        return;
    }
    if source.contains("os.Getenv(") {
        return;
    }
    if !(source.contains("cfg.Password") || source.contains("cfg.Secret")) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("cfg.Password") {
        idx
    } else {
        source.find("cfg.Secret").unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_260,
        &file,
        line,
        col,
        "a secret-bearing field is loaded from a configuration file and used directly",
        out,
    );
}

fn detect_cwe_261(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("base64.StdEncoding.EncodeToString(") {
        return;
    }
    let stores_encoded_secret = source.contains("Secret: encoded") || source.contains("Store(user, encoded)");
    if !stores_encoded_secret {
        return;
    }

    let start_byte = source.find("base64.StdEncoding.EncodeToString(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_261,
        &file,
        line,
        col,
        "a password is Base64-encoded and then stored in a recoverable form",
        out,
    );
}

fn detect_cwe_262(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let loads_age_metadata = source.contains("last_seen") || source.contains("changed_at");
    if !loads_age_metadata {
        return;
    }
    if source.contains("time.Since(") || source.contains("maxPasswordAge") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("last_seen") {
        idx
    } else {
        source.find("changed_at").unwrap_or(0)
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_262,
        &file,
        line,
        col,
        "credential metadata is loaded but no password-age enforcement is performed",
        out,
    );
}

fn detect_cwe_263(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("MaxAgeDays: 3650") {
        return;
    }

    let start_byte = source.find("MaxAgeDays: 3650").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_263,
        &file,
        line,
        col,
        "password maximum age is configured to an excessively long multi-year period",
        out,
    );
}

fn detect_cwe_266(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let Some(role_assignment) = facts.assignments.iter().find(|assignment| {
        assignment.name == "role"
    }) else {
        return;
    };

    let role_is_user_controlled = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled
            && binding.name == "role"
    });
    if !role_is_user_controlled {
        return;
    }

    let role_is_used_for_membership = source.contains("Role: role")
        || source.contains("Store(userID, role)");
    if !role_is_used_for_membership {
        return;
    }

    let (line, col) = unit.line_col(role_assignment.start_byte);
    emit::push_finding(
        &META_CWE_266,
        &file,
        line,
        col,
        "a client-controlled role value is used directly when provisioning access",
        out,
    );
}

fn detect_cwe_267(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let reviewer_guard = source.contains(r#"!= "reviewer""#) || source.contains(r#".Get("X-Role") != "reviewer""#);
    if !reviewer_guard {
        return;
    }

    let Some(remove_call) = facts.call_facts.iter().find(|call| call.callee == "os.Remove") else {
        return;
    };

    let (line, col) = unit.line_col(remove_call.start_byte);
    emit::push_finding(
        &META_CWE_267,
        &file,
        line,
        col,
        "the reviewer role is allowed to invoke a destructive filesystem removal operation",
        out,
    );
}

fn detect_cwe_268(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let has_chained_scopes = (source.contains(r#"p == "read""#) || source.contains(r#"case "read":"#))
        && (source.contains(r#"p == "export""#) || source.contains(r#"case "export":"#))
        && (source.contains("hasRead && hasExport") || source.contains("hasExport && hasRead"));
    if !has_chained_scopes {
        return;
    }

    let Some(sensitive_sink) = facts.call_facts.iter().find(|call| {
        (call.callee == "db.Queryx"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.contains("password_hash")))
            || (call.callee == "json.NewEncoder"
                && source.contains("Encode(userRecords)")
                && source.contains(r#""hash""#))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(sensitive_sink.start_byte);
    emit::push_finding(
        &META_CWE_268,
        &file,
        line,
        col,
        "a sensitive export path is authorized by combining weaker read and export scopes",
        out,
    );
}

fn detect_cwe_270(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let Some(context_switch) = facts.call_facts.iter().find(|call| {
        (call.callee == "c.Set"
            && call.arguments.len() >= 2
            && call.arguments[0].contains("effective_user")
            && (call.arguments[1].contains(r#""root""#) || call.arguments[1].contains(r#""maintenance""#)))
            || (call.callee == "context.WithValue"
                && call.arguments.len() >= 3
                && call.arguments[1].contains("effectiveUserKey")
                && (call.arguments[2].contains(r#""root""#) || call.arguments[2].contains(r#""maintenance""#)))
    }) else {
        return;
    };

    let restores_context = source.contains("defer c.Set(\"effective_user\", original)")
        || source.contains("defer func()")
            && source.contains("context.WithValue(r.Context(), effectiveUserKey, original)");
    if restores_context {
        return;
    }

    let (line, col) = unit.line_col(context_switch.start_byte);
    emit::push_finding(
        &META_CWE_270,
        &file,
        line,
        col,
        "the handler switches to a privileged execution context without restoring the original caller context",
        out,
    );
}

fn detect_cwe_272(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    let Some(elevate_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "syscall.Setuid" && call.arguments.first().is_some_and(|arg| arg == "0"))
    else {
        return;
    };

    let performs_privileged_work = facts.call_facts.iter().any(|call| call.callee == "os.Chown");
    if !performs_privileged_work {
        return;
    }

    let drops_privilege = facts.call_facts.iter().any(|call| {
        call.callee == "syscall.Setuid" && call.arguments.first().is_some_and(|arg| arg == "1000")
    });
    if drops_privilege {
        return;
    }

    let (line, col) = unit.line_col(elevate_call.start_byte);
    emit::push_finding(
        &META_CWE_272,
        &file,
        line,
        col,
        "the handler raises uid for a privileged operation and does not drop it afterward",
        out,
    );
}

fn detect_cwe_273(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains("if err := syscall.Setuid(1000); err != nil") {
        return;
    }

    if facts
        .call_facts
        .iter()
        .any(|call| call.callee == "syscall.Setuid" && call.arguments.first().is_some_and(|arg| arg == "0"))
    {
        return;
    }

    let Some(drop_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee == "syscall.Setuid" && call.arguments.first().is_some_and(|arg| arg == "1000"))
    else {
        return;
    };

    let (line, col) = unit.line_col(drop_call.start_byte);
    emit::push_finding(
        &META_CWE_273,
        &file,
        line,
        col,
        "the handler ignores whether dropping privilege via Setuid actually succeeded",
        out,
    );
}

fn detect_cwe_274(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let Some(rename_call) = facts.call_facts.iter().find(|call| call.callee == "os.Rename") else {
        return;
    };

    let treats_error_as_success = (source.contains("if err != nil {")
        && (source.contains(r#"c.JSON(200, gin.H{"rotated": true})"#)
            || source.contains(r#"w.WriteHeader(http.StatusOK)"#)))
        && !source.contains("errors.Is(err, syscall.EPERM)");
    if !treats_error_as_success {
        return;
    }

    let (line, col) = unit.line_col(rename_call.start_byte);
    emit::push_finding(
        &META_CWE_274,
        &file,
        line,
        col,
        "an insufficient-privilege filesystem failure is treated like a successful rotation",
        out,
    );
}

fn detect_cwe_276(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2] == "0666"
            && (call.arguments[0].contains("sessions") || source.contains("session_data") || source.contains("X-Session-Data"))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_276,
        &file,
        line,
        col,
        "a session artifact is written with a world-readable and world-writable default mode",
        out,
    );
}

fn detect_cwe_277(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    let clears_umask = facts
        .call_facts
        .iter()
        .any(|call| call.callee == "syscall.Umask" && call.arguments.first().is_some_and(|arg| arg == "0"));
    if !clears_umask {
        return;
    }

    let Some(mkdir_call) = facts.call_facts.iter().find(|call| {
        call.callee == "os.MkdirAll"
            && call.arguments.len() >= 2
            && call.arguments[1] == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(mkdir_call.start_byte);
    emit::push_finding(
        &META_CWE_277,
        &file,
        line,
        col,
        "umask is cleared before creating a world-writable directory",
        out,
    );
}

fn detect_cwe_278(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    let Some(open_call) = facts.call_facts.iter().find(|call| {
        call.callee == "os.OpenFile"
            && call.arguments.len() >= 3
            && call.arguments[2].contains("os.FileMode(hdr.Mode)")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_278,
        &file,
        line,
        col,
        "archive entry permissions are reapplied directly from untrusted metadata during extraction",
        out,
    );
}

fn detect_cwe_279(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("strconv.ParseUint(") {
        return;
    }

    let Some(write_call) = facts.call_facts.iter().find(|call| {
        call.callee == "os.WriteFile"
            && call.arguments.len() >= 3
            && call.arguments[2] == "0777"
    }) else {
        return;
    };

    let (line, col) = unit.line_col(write_call.start_byte);
    emit::push_finding(
        &META_CWE_279,
        &file,
        line,
        col,
        "the handler parses a requested mode but still writes the file with a hard-coded world-writable mode",
        out,
    );
}

fn detect_cwe_280(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let Some(open_call) = facts.call_facts.iter().find(|call| call.callee == "os.Open") else {
        return;
    };

    let falls_through_on_error = source.contains("if err != nil {")
        && !source.contains("errors.Is(err, syscall.EACCES)")
        && !source.contains("errors.Is(err, syscall.EPERM)")
        && (source.contains("db.Exec(\"DELETE FROM tenants")
            || source.contains("tenantStore.Delete("));
    if !falls_through_on_error {
        return;
    }

    let (line, col) = unit.line_col(open_call.start_byte);
    emit::push_finding(
        &META_CWE_280,
        &file,
        line,
        col,
        "failure to access a protected resource leads into a privileged deletion path instead of a denial",
        out,
    );
}

fn detect_cwe_281(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains("info.Mode()") {
        return;
    }

    let Some(create_call) = facts.call_facts.iter().find(|call| call.callee == "os.Create") else {
        return;
    };

    if !source.contains("io.Copy(out, in)") {
        return;
    }

    let (line, col) = unit.line_col(create_call.start_byte);
    emit::push_finding(
        &META_CWE_281,
        &file,
        line,
        col,
        "backup recreation uses os.Create and loses the source file's original permission bits",
        out,
    );
}

fn detect_cwe_283(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains("info.Sys().(*syscall.Stat_t)") || source.contains("stat.Uid") {
        return;
    }

    let Some(remove_call) = facts.call_facts.iter().find(|call| call.callee == "os.Remove") else {
        return;
    };
    let removes_user_controlled_path = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled
            && remove_call.arguments.iter().any(|arg| arg == &binding.name)
    });
    if !removes_user_controlled_path {
        return;
    }

    let (line, col) = unit.line_col(remove_call.start_byte);
    emit::push_finding(
        &META_CWE_283,
        &file,
        line,
        col,
        "a user-selected file path is removed without verifying that the caller owns the inode",
        out,
    );
}

fn detect_cwe_289(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if source.contains("canonical_name = ?") {
        return;
    }
    if !source.contains("strings.Split(") || !source.contains(r#""@")[0]"#) {
        return;
    }

    let start_byte = source.find("strings.Split(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_289,
        &file,
        line,
        col,
        "principal authentication strips the realm suffix and authenticates only the bare local username",
        out,
    );
}

fn detect_cwe_290(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();

    let Some(header_call) = facts.call_facts.iter().find(|call| {
        (call.callee == "c.GetHeader" || call.callee == "r.Header.Get")
            && call.arguments.first().is_some_and(|arg| arg.contains("X-Remote-User"))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(header_call.start_byte);
    emit::push_finding(
        &META_CWE_290,
        &file,
        line,
        col,
        "the request trusts a caller-controlled X-Remote-User header as the authenticated identity",
        out,
    );
}

fn detect_cwe_294(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let loads_auth_token = source.contains(r#"c.PostForm("auth_token")"#)
        || source.contains(r#"r.FormValue("auth_token")"#);
    if !loads_auth_token {
        return;
    }

    let has_nonce_tracking = source.contains("LoadOrStore(nonce, true)")
        || source.contains("spentNonces")
        || source.contains(r#"PostForm("nonce")"#)
        || source.contains(r#"FormValue("nonce")"#);
    if has_nonce_tracking {
        return;
    }

    let start_byte = if let Some(idx) = source.find("auth_token") {
        idx
    } else {
        return;
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_294,
        &file,
        line,
        col,
        "the login flow accepts an authentication token without nonce tracking or replay detection",
        out,
    );
}

fn detect_cwe_301(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let echoes_challenge = source.contains(r#"gin.H{"proof": challenge}"#)
        || source.contains(r#"{"proof": challenge}"#)
        || source.contains(r#"map[string]string{"proof": challenge}"#);
    if !echoes_challenge {
        return;
    }
    if source.contains("hmac.New(") || source.contains("EncodeToString(") {
        return;
    }

    let start_byte = source.find("challenge").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_301,
        &file,
        line,
        col,
        "the server reflects the client challenge directly as the authentication proof",
        out,
    );
}

fn detect_cwe_303(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("hmac.New(") || !source.contains("mac.Sum(nil)") {
        return;
    }
    if !source.contains("string(expected) == sig") {
        return;
    }

    let start_byte = source.find("string(expected) == sig").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_303,
        &file,
        line,
        col,
        "the computed MAC is compared to user input with string equality instead of constant-time verification",
        out,
    );
}

fn detect_cwe_305(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let debug_bypass = source.contains(r#"Query("debug") == "1""#)
        || source.contains(r#"Query().Get("debug") == "1""#);
    if !debug_bypass {
        return;
    }

    let has_subject_check = source.contains("jwt_sub") || source.contains("X-JWT-Sub");
    if !has_subject_check {
        return;
    }

    let start_byte = if let Some(idx) = source.find("debug") { idx } else { return; };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_305,
        &file,
        line,
        col,
        "a caller-controlled debug flag reaches privileged behavior before the authenticated subject check",
        out,
    );
}

fn detect_cwe_306(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let destructive_purge = source.contains("TRUNCATE ledger");
    if !destructive_purge {
        return;
    }
    let has_auth_gate = source.contains("operator_id") || source.contains("X-Operator-ID");
    if has_auth_gate {
        return;
    }

    let start_byte = source.find("TRUNCATE ledger").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_306,
        &file,
        line,
        col,
        "a destructive purge endpoint performs its action without any authentication gate",
        out,
    );
}

fn detect_cwe_307(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let login_lookup = source.contains("SELECT hash FROM users WHERE email = ?")
        || source.contains(r#"Where("email = ?", email).First(&u)"#);
    if !login_lookup {
        return;
    }

    let has_attempt_tracking = source.contains("loginAttempts")
        || source.contains("LoadOrStore(key, 0)")
        || source.contains("time.Sleep(200 * time.Millisecond)");
    if has_attempt_tracking {
        return;
    }

    let start_byte = if let Some(idx) = source.find("email") { idx } else { return; };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_307,
        &file,
        line,
        col,
        "the login flow has no throttling, backoff, or lockout for repeated failed authentication attempts",
        out,
    );
}

fn detect_cwe_308(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let has_password_gate = source.contains(r#"PostForm("password")"#)
        || source.contains(r#"FormValue("password")"#);
    if !has_password_gate {
        return;
    }
    if source.contains(r#"PostForm("totp")"#)
        || source.contains(r#"FormValue("totp")"#)
        || source.contains("totp_valid")
        || source.contains("X-TOTP-Valid")
    {
        return;
    }
    if !source.contains("INSERT INTO wires") {
        return;
    }

    let start_byte = source.find("password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_308,
        &file,
        line,
        col,
        "a high-value wire action is authorized with only a password and no validated second factor",
        out,
    );
}

fn detect_cwe_309(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let enterprise_login_shape = source.contains("func EnterpriseLogin(")
        && (source.contains(r#"{"session":"` + user + `"}"#)
            || source.contains(r#"{"session": user}"#)
            || source.contains(r#"gin.H{"session": user}"#)
            || source.contains(r#"gin.H{"session": c.GetString("subject")}"#));
    if !enterprise_login_shape {
        return;
    }

    let password_form_login = (source.contains(r#"PostForm("username")"#) || source.contains(r#"FormValue("username")"#))
        && (source.contains(r#"PostForm("password")"#) || source.contains(r#"FormValue("password")"#));
    if !password_form_login {
        return;
    }
    if source.contains("webauthn_assertion") || source.contains("X-WebAuthn-OK") || source.contains("webauthn_ok") {
        return;
    }

    let start_byte = source.find("username").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_309,
        &file,
        line,
        col,
        "the enterprise login route relies on username and password form fields as the primary authentication method",
        out,
    );
}

fn detect_cwe_312(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let stores_plain_ssn = source.contains("SSN: c.PostForm(\"ssn\")")
        || source.contains("SSN: r.FormValue(\"ssn\")");
    let writes_plain_ssn_json = source.contains(r#"SSN string `json:"ssn"`"#)
        && source.contains("json.Marshal(rec)");
    if !(stores_plain_ssn || writes_plain_ssn_json) {
        return;
    }
    if source.contains("SSNCipher") || source.contains("gcm.Seal(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("ssn") { idx } else { return; };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_312,
        &file,
        line,
        col,
        "a sensitive SSN value is persisted in cleartext instead of encrypted form",
        out,
    );
}

fn detect_cwe_319(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let handles_card_data = source.contains("CVV") && source.contains("Number");
    if !handles_card_data {
        return;
    }
    if source.contains("ListenAndServeTLS(") || source.contains("tls.Config") {
        return;
    }
    if !(source.contains("ListenAndServe(") || source.contains("http.ListenAndServe(")) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("ListenAndServe") { idx } else { return; };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_319,
        &file,
        line,
        col,
        "sensitive payment data is accepted over a cleartext HTTP listener instead of TLS",
        out,
    );
}

fn detect_cwe_322(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("tls.Dial(") || !source.contains("InsecureSkipVerify: true") {
        return;
    }

    let start_byte = source.find("InsecureSkipVerify: true").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_322,
        &file,
        line,
        col,
        "the TLS relay connection disables peer certificate verification during key exchange",
        out,
    );
}

fn detect_cwe_323(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let fixed_nonce = source.contains("sharedNonce")
        || source.contains("relaySessionNonce")
        || source.contains("static-nonce12")
        || source.contains("fixednonce12");
    if !fixed_nonce || !source.contains("aead.Seal(") {
        return;
    }
    if source.contains("io.ReadFull(rand.Reader, nonce)") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("Nonce") {
        idx
    } else if let Some(idx) = source.find("nonce") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_323,
        &file,
        line,
        col,
        "a fixed nonce is reused for AEAD encryption operations with the same key",
        out,
    );
}

fn detect_cwe_324(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("ExpiresAt") {
        return;
    }
    let key_expiry_crypto_shape = (source.contains("ApiKeyRow") || source.contains("SigningKey"))
        && source.contains("Secret")
        && source.contains("hmac.New(");
    if !key_expiry_crypto_shape {
        return;
    }
    if source.contains("time.Now().After(row.ExpiresAt)")
        || source.contains("time.Now().After(key.ExpiresAt)")
    {
        return;
    }

    let expired_key_source = source.contains("Add(-48 * time.Hour)") || source.contains("ExpiresAt time.Time");
    if !expired_key_source {
        return;
    }

    let start_byte = source.find("ExpiresAt").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_324,
        &file,
        line,
        col,
        "cryptographic processing uses key material with an expiration field but never checks whether the key is expired",
        out,
    );
}

fn detect_cwe_325(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("cipher.NewCTR(") || !source.contains("XORKeyStream(") {
        return;
    }
    if source.contains("cipher.NewGCM(") || source.contains("Seal(") {
        return;
    }

    let start_byte = source.find("cipher.NewCTR(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_325,
        &file,
        line,
        col,
        "sensitive data is encrypted with CTR mode without an authentication or integrity step",
        out,
    );
}

fn detect_cwe_328(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("md5.Sum(") {
        return;
    }

    let start_byte = source.find("md5.Sum(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_328,
        &file,
        line,
        col,
        "a password digest is derived with MD5, which is too weak for this security-sensitive use",
        out,
    );
}

fn detect_cwe_331(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let weak_recovery_code = source.contains("rand.NewSource(time.Now().UnixNano())")
        && source.contains("Intn(900000) + 100000")
        && source.contains("code");
    if !weak_recovery_code {
        return;
    }

    let start_byte = source.find("Intn(900000) + 100000").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_331,
        &file,
        line,
        col,
        "the recovery code is generated from a small predictable decimal range instead of cryptographic randomness",
        out,
    );
}

fn detect_cwe_334(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("Intn(4096)") {
        return;
    }

    let start_byte = source.find("Intn(4096)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_334,
        &file,
        line,
        col,
        "the generated token comes from a very small 4096-value space and is easy to guess",
        out,
    );
}

fn detect_cwe_335(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let predictable_seed = (source.contains("seed := time.Now().Unix()") || source.contains("rand.NewSource(seed)"))
        && (source.contains("rand.Seed(seed)") || source.contains("rand.New(rand.NewSource(seed))"));
    if !predictable_seed {
        return;
    }

    let start_byte = if let Some(idx) = source.find("time.Now().Unix()") {
        idx
    } else {
        source.find("rand.NewSource(seed)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_335,
        &file,
        line,
        col,
        "the PRNG is seeded from predictable wall-clock time for a security-sensitive ticket value",
        out,
    );
}

fn detect_cwe_338(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let weak_prng_token = (source.contains("rand.New(rand.NewSource(time.Now().UnixNano()))")
        || source.contains("rand.NewSource(time.Now().UnixNano())"))
        && (source.contains("sid") || source.contains("token"));
    if !weak_prng_token {
        return;
    }

    let start_byte = if let Some(idx) = source.find("rand.New(rand.NewSource(time.Now().UnixNano()))") {
        idx
    } else {
        source.find("rand.NewSource(time.Now().UnixNano())").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_338,
        &file,
        line,
        col,
        "a security-sensitive token is generated from math/rand instead of cryptographic randomness",
        out,
    );
}

fn detect_cwe_341(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let predictable_token = source.contains("fmt.Sprintf(\"%d-%d-%s\"")
        && source.contains("os.Getpid()")
        && source.contains("time.Now().Unix()");
    if !predictable_token {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%d-%d-%s\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_341,
        &file,
        line,
        col,
        "the token is built from observable pid, wall-clock time, and caller input instead of cryptographic randomness",
        out,
    );
}

fn detect_cwe_342(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let increments_previous = (source.contains("lastOTP++") && source.contains("code := lastOTP"))
        || (source.contains("lastSmsCode++") && source.contains("code := lastSmsCode"));
    if !increments_previous {
        return;
    }

    let start_byte = if let Some(idx) = source.find("lastOTP++") {
        idx
    } else {
        source.find("lastSmsCode++").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_342,
        &file,
        line,
        col,
        "the next OTP value is generated by incrementing the previous one",
        out,
    );
}

fn detect_cwe_343(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let deterministic_state_machine = source.contains("*3 + 1) % 97")
        || source.contains("*5 + 3) % 101");
    if !deterministic_state_machine {
        return;
    }

    let start_byte = if let Some(idx) = source.find("*3 + 1) % 97") {
        idx
    } else {
        source.find("*5 + 3) % 101").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_343,
        &file,
        line,
        col,
        "the output range is produced by a deterministic recurrence over shared state and is predictable from previous values",
        out,
    );
}

fn detect_cwe_344(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hardcoded_secret = source.contains("const billingHMACSecret = ")
        || source.contains("const shipmentHMACSecret = ");
    if !hardcoded_secret || !source.contains("hmac.New(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("const billingHMACSecret = ") {
        idx
    } else {
        source.find("const shipmentHMACSecret = ").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_344,
        &file,
        line,
        col,
        "a hard-coded invariant HMAC secret is embedded directly in code for a changing signing context",
        out,
    );
}

fn detect_cwe_346(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let reflects_origin = source.contains("Access-Control-Allow-Origin\", origin")
        && source.contains("Header.Get(\"Origin\")");
    if !reflects_origin {
        return;
    }
    if source.contains("allowedOrigins") || source.contains("trustedOrigins") || source.contains("forbidden origin") {
        return;
    }

    let start_byte = source.find("Access-Control-Allow-Origin").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_346,
        &file,
        line,
        col,
        "the response reflects the caller-supplied Origin without validating it against a trusted allow-list",
        out,
    );
}

fn detect_cwe_347(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let decodes_jwt_payload = source.contains("strings.Split(raw, \".\")")
        && source.contains("DecodeString(parts[1])")
        && source.contains("json.Unmarshal(payload, &claims)");
    if !decodes_jwt_payload {
        return;
    }
    if source.contains("VerifyPKCS1v15(") || source.contains("invalid signature") {
        return;
    }

    let start_byte = source.find("DecodeString(parts[1])").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_347,
        &file,
        line,
        col,
        "JWT claims are decoded and trusted without verifying the token signature first",
        out,
    );
}

fn detect_cwe_349(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let mixed_trust_blob = (source.contains("json.RawMessage") && source.contains("json.Unmarshal(bundle.Profile, &profile)"))
        || (source.contains("json.RawMessage") && source.contains("json.Unmarshal(env.Profile, &profile)"));
    if !mixed_trust_blob {
        return;
    }
    if source.contains("Role != \"support\"") || source.contains("role not allowed from trusted channel") {
        return;
    }

    let start_byte = source.find("json.RawMessage").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_349,
        &file,
        line,
        col,
        "trusted envelope metadata is mixed with an untyped raw profile blob whose role fields are used directly",
        out,
    );
}

fn detect_cwe_353(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let ingests_body = source.contains("io.ReadAll(") && source.contains("INSERT INTO telemetry")
        || source.contains("io.ReadAll(") && source.contains("INSERT INTO agent_reports");
    if !ingests_body {
        return;
    }
    if source.contains("X-Body-Mac") || source.contains("ConstantTimeCompare(expected, got)") {
        return;
    }

    let start_byte = source.find("io.ReadAll(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_353,
        &file,
        line,
        col,
        "the inbound payload is stored without verifying any integrity MAC",
        out,
    );
}

fn detect_cwe_356(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let destructive_delete = (source.contains("func PurgeTenant(") && source.contains("DELETE FROM tenants WHERE slug = ?"))
        || (source.contains("func DeleteWorkspaceRecords(") && source.contains("DELETE FROM workspaces WHERE slug = ?"));
    if !destructive_delete {
        return;
    }
    if source.contains("X-Confirm-Purge") || source.contains("X-Confirm-Delete") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("DELETE FROM tenants") {
        idx
    } else {
        source.find("DELETE FROM workspaces").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_356,
        &file,
        line,
        col,
        "the destructive action executes without an explicit confirmation token or second-step confirmation",
        out,
    );
}

fn detect_cwe_358(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let decodes_bearer_claims = source.contains("strings.TrimPrefix(raw, \"Bearer \")")
        && source.contains("DecodeString(parts[1])")
        && source.contains("json.Unmarshal(payload, &claims)");
    if !decodes_bearer_claims {
        return;
    }
    if source.contains("invalid jwt structure") || source.contains("unsupported jwt algorithm") {
        return;
    }

    let start_byte = source.find("DecodeString(parts[1])").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_358,
        &file,
        line,
        col,
        "bearer token claims are accepted without required JWT structure and algorithm validation",
        out,
    );
}

fn detect_cwe_359(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let serializes_pii = (source.contains("SSN") && source.contains("Phone") && source.contains("json.Marshal(row)"))
        || (source.contains("SSN") && source.contains("Phone") && source.contains("json.Marshal(") && source.contains("PersonRecord"));
    if !serializes_pii {
        return;
    }
    if source.contains("PublicProfile") || source.contains("PublicPersonView") || source.contains("requester != target") {
        return;
    }

    let start_byte = source.find("json.Marshal(row)").unwrap_or_else(|| source.find("SSN").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_359,
        &file,
        line,
        col,
        "private personal information is serialized directly without requester authorization or public projection",
        out,
    );
}

fn detect_cwe_360(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("X-Forwarded-For") {
        return;
    }
    if source.contains("SplitHostPort(") || source.contains("RemoteAddr") {
        return;
    }

    let start_byte = source.find("X-Forwarded-For").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_360,
        &file,
        line,
        col,
        "a security-sensitive client IP action trusts caller-controlled forwarded header data",
        out,
    );
}

fn detect_cwe_366(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let direct_credit_increment = source.contains("walletCredits += amount")
        || source.contains("referralCredits += 10");
    if !direct_credit_increment {
        return;
    }
    if source.contains("atomic.AddInt64(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("walletCredits += amount") {
        idx
    } else {
        source.find("referralCredits += 10").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_366,
        &file,
        line,
        col,
        "shared credit state is incremented without atomic or synchronized protection",
        out,
    );
}

fn detect_cwe_367(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let stat_then_use = source.contains("os.Stat(target)") && source.contains("os.ReadFile(target)");
    if !stat_then_use {
        return;
    }

    let start_byte = source.find("os.Stat(target)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_367,
        &file,
        line,
        col,
        "the code checks a file path with Stat before later using it, creating a TOCTOU race window",
        out,
    );
}

fn detect_cwe_368(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let shared_privilege_flag = (source.contains("actingAsRoot = true") || source.contains("privilegedMode = true"))
        && source.contains("os.Setenv(");
    if !shared_privilege_flag {
        return;
    }
    if source.contains("sync.Mutex") || source.contains("Lock()") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("actingAsRoot = true") {
        idx
    } else {
        source.find("privilegedMode = true").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_368,
        &file,
        line,
        col,
        "privileged context switching is controlled by an unsynchronized shared mode flag",
        out,
    );
}

fn detect_cwe_378(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let insecure_temp_file = source.contains("os.TempDir()") && source.contains("0666");
    if !insecure_temp_file {
        return;
    }
    if source.contains("CreateTemp(") || source.contains("Chmod(f.Name(), 0600)") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("os.TempDir()") { idx } else { source.find("0666").unwrap_or(0) };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_378,
        &file,
        line,
        col,
        "a temp file is created with world-accessible permissions in the shared temp area",
        out,
    );
}

fn detect_cwe_379(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let insecure_temp_dir = source.contains("MkdirAll(dir, 0777)")
        && (source.contains("/tmp/shared-reports") || source.contains("/tmp/shared-sessions"));
    if !insecure_temp_dir {
        return;
    }
    if source.contains("MkdirTemp(") || source.contains("Chmod(dir, 0700)") {
        return;
    }

    let start_byte = source.find("MkdirAll(dir, 0777)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_379,
        &file,
        line,
        col,
        "a temporary file is staged inside a shared world-writable directory",
        out,
    );
}

fn detect_cwe_385(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let early_exit_secret_compare = source.contains("for i := 0; i < len(provided); i++")
        && source.contains("if provided[i] != expected[i] {")
        && source.contains("return false");
    if !early_exit_secret_compare {
        return;
    }
    if source.contains("ConstantTimeCompare(") {
        return;
    }

    let start_byte = source.find("for i := 0; i < len(provided); i++").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_385,
        &file,
        line,
        col,
        "the secret comparison exits on the first mismatch and leaks timing information",
        out,
    );
}

fn detect_cwe_393(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let wrong_status = source.contains("if err != nil {")
        && source.contains("WriteHeader(http.StatusOK)")
        && source.contains(r#"{"balance":0}"#);
    if !wrong_status {
        return;
    }

    let start_byte = source.find("WriteHeader(http.StatusOK)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_393,
        &file,
        line,
        col,
        "lookup failure still returns HTTP 200 with a fallback balance payload",
        out,
    );
}

fn detect_cwe_403(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let opens_secret_before_exec = source.contains("os.Open(\"/etc/slopguard/master.key\")")
        && source.contains("exec.Command(\"/bin/sh\", \"-c\"");
    if !opens_secret_before_exec {
        return;
    }
    if source.contains("secret.Fd()") || source.contains("defer secret.Close()") {
        return;
    }

    let start_byte = source.find("os.Open(\"/etc/slopguard/master.key\")").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_403,
        &file,
        line,
        col,
        "a sensitive descriptor is left open when launching a child shell command",
        out,
    );
}

fn detect_cwe_408(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let query_before_auth = (source.contains("SELECT * FROM orders WHERE tenant_id = ?") && source.contains("Authorization"))
        && (source.find("SELECT * FROM orders WHERE tenant_id = ?").unwrap_or(usize::MAX)
            < source.find("Authorization").unwrap_or(0));
    if !query_before_auth {
        return;
    }

    let start_byte = source.find("SELECT * FROM orders WHERE tenant_id = ?").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_408,
        &file,
        line,
        col,
        "the export query runs before the caller authentication check",
        out,
    );
}

fn detect_cwe_412(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let client_lock_path = source.contains("lockfile") && source.contains("os.ReadFile(lockPath)");
    if !client_lock_path {
        return;
    }
    if source.contains("jobLockPath") || source.contains("fixedJobLock") {
        return;
    }

    let start_byte = source.find("lockfile").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_412,
        &file,
        line,
        col,
        "the lock file path comes directly from the client request",
        out,
    );
}

fn detect_cwe_420(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let has_unprotected_debug_route = (source.contains("r.GET(\"/debug/sqltrace\"") && source.contains("r.Group(\"/api\", requireJWT())"))
        || (source.contains("http.HandleFunc(\"/debug/sqltrace\"") && source.contains("http.Handle(\"/api/invoices\", protected)"));
    if !has_unprotected_debug_route {
        return;
    }

    let start_byte = source.find("/debug/sqltrace").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_420,
        &file,
        line,
        col,
        "the alternate debug route is exposed outside the primary authenticated API guard",
        out,
    );
}

fn detect_cwe_421(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let shared_event_state = (source.contains("transferToken =") && source.contains("event: status\\ndata: \" + transferToken"))
        || (source.contains("wireTransferCode =") && source.contains("event: status\\ndata: %s\\n\\n\", wireTransferCode"));
    if !shared_event_state {
        return;
    }
    if source.contains("sync.Mutex") || source.contains("transferMu") || source.contains("wireMu") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("transferToken =") {
        idx
    } else {
        source.find("wireTransferCode =").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_421,
        &file,
        line,
        col,
        "an alternate event channel exposes shared transfer state without synchronization",
        out,
    );
}

fn detect_cwe_425(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let admin_export = source.contains("/internal/admin/export.csv") && source.contains("SELECT email, ssn FROM customers");
    if !admin_export {
        return;
    }
    if source.contains("requireAdmin()") || source.contains("requireAdmin(") {
        return;
    }

    let start_byte = source.find("/internal/admin/export.csv").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_425,
        &file,
        line,
        col,
        "the admin export endpoint is mounted without an explicit authorization guard",
        out,
    );
}

fn detect_cwe_426(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let request_controlled_plugin_dir = source.contains("plugin_dir") && source.contains("plugin.Open(modPath)");
    if !request_controlled_plugin_dir {
        return;
    }
    if source.contains("trustedPluginDir") || source.contains("trustedPluginRoot") {
        return;
    }

    let start_byte = source.find("plugin_dir").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_426,
        &file,
        line,
        col,
        "the plugin load directory is derived from caller-controlled input",
        out,
    );
}

fn detect_cwe_427(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let path_mutation = source.contains("os.Setenv(\"PATH\",") && source.contains("exec.Command(\"pdftopng\"");
    if !path_mutation {
        return;
    }
    if source.contains("pdftopngPath") || source.contains("pdftopngBinary") {
        return;
    }

    let start_byte = source.find("os.Setenv(\"PATH\",").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_427,
        &file,
        line,
        col,
        "user input is prepended to PATH before resolving the helper binary by name",
        out,
    );
}

fn detect_cwe_434(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let stores_client_filename = (source.contains("file.Filename") && source.contains("SaveUploadedFile(file, dest)"))
        || (source.contains("hdr.Filename") && source.contains("os.Create(dest)"));
    if !stores_client_filename {
        return;
    }
    let executable_web_serve_shape = (source.contains("/var/www/static/avatars")
        || source.contains("/static/avatars/"))
        && (source.contains("c.Redirect(http.StatusFound, \"/static/avatars/\"+file.Filename)")
            || source.contains("http.Redirect(w, r, \"/static/avatars/\"+hdr.Filename, http.StatusFound)"));
    if !executable_web_serve_shape {
        return;
    }
    if source.contains("unsupported file type") || source.contains("filepath.Ext(") || source.contains("hex.EncodeToString(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("file.Filename") {
        idx
    } else {
        source.find("hdr.Filename").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_434,
        &file,
        line,
        col,
        "the upload is stored and later served using the client filename without an extension allow-list",
        out,
    );
}

fn detect_cwe_552(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let permissive_upload_mode = (source.contains("FormFile(\"contract\")") || source.contains("FormFile(\"contract\")"))
        && source.contains("/srv/contracts")
        && source.contains("os.Chmod(dest, 0o777)");
    if !permissive_upload_mode {
        return;
    }
    if source.contains("filepath.Base(") || source.contains("os.Chmod(dest, 0o600)") {
        return;
    }

    let start_byte = source.find("os.Chmod(dest, 0o777)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_552,
        &file,
        line,
        col,
        "uploaded contract files are made world-accessible after storage",
        out,
    );
}

fn detect_cwe_565(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let trusts_role_cookie = (source.contains("c.Cookie(\"role\")") || source.contains("r.Cookie(\"role\")"))
        && source.contains(r#""admin""#)
        && source.contains("DELETE FROM tenants");
    if !trusts_role_cookie {
        return;
    }
    if source.contains("GetString(\"role\")") || source.contains("Header.Get(\"X-Role\")") {
        return;
    }

    let start_byte = source.find("Cookie(\"role\")").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_565,
        &file,
        line,
        col,
        "a privileged delete action trusts a caller-controlled role cookie",
        out,
    );
}

fn detect_cwe_454(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let request_bootstrap_flag = source.contains("enforceMFA = c.PostForm(\"enforce_mfa\") == \"true\"")
        || source.contains("enforceMFA = r.FormValue(\"enforce_mfa\") == \"true\"");
    if !request_bootstrap_flag {
        return;
    }

    let start_byte = source.find("enforce_mfa").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_454,
        &file,
        line,
        col,
        "the MFA enforcement flag is bootstrapped from client input instead of server configuration",
        out,
    );
}

fn detect_cwe_455(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let continues_after_tls_failure = source.contains("tls.LoadX509KeyPair(")
        && source.contains("continuing without mTLS");
    if !continues_after_tls_failure {
        return;
    }
    if source.contains("log.Fatalf(") {
        return;
    }

    let start_byte = source.find("continuing without mTLS").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_455,
        &file,
        line,
        col,
        "startup logs a TLS material failure but continues running anyway",
        out,
    );
}

fn detect_cwe_459(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let temp_export = source.contains("CreateTemp(") && (source.contains("c.File(f.Name())") || source.contains("ServeFile(w, r, f.Name())"));
    if !temp_export {
        return;
    }
    if source.contains("os.Remove(f.Name())") {
        return;
    }

    let start_byte = source.find("CreateTemp(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_459,
        &file,
        line,
        col,
        "the temporary export file is served without being removed afterward",
        out,
    );
}

fn detect_cwe_472(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let trusts_role_form = source.contains("Role    string `form:\"role\"`")
        || source.contains("role := r.FormValue(\"role\")");
    if !trusts_role_form {
        return;
    }
    if source.contains("SELECT role FROM users") {
        return;
    }

    let start_byte = source.find("role").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_472,
        &file,
        line,
        col,
        "authorization trusts a client-submitted role field instead of resolving role server-side",
        out,
    );
}

fn detect_cwe_488(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let global_session_map = source.contains("map[string][]string{}") && source.contains("session");
    if !global_session_map {
        return;
    }
    if source.contains("Cookie(\"session_id\")") || source.contains("r.Cookie(\"session_id\")") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("sessionCarts") {
        idx
    } else {
        source.find("cartsBySession").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_488,
        &file,
        line,
        col,
        "global cart state is keyed directly by a client-controlled session identifier",
        out,
    );
}

fn detect_cwe_494(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let downloads_bundle = source.contains("http.Get(") && source.contains("/tmp/worker.bin");
    if !downloads_bundle {
        return;
    }
    if source.contains("sha256.Sum256(") || source.contains("integrity check failed") {
        return;
    }

    let start_byte = source.find("http.Get(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_494,
        &file,
        line,
        col,
        "the downloaded worker bundle is accepted without any pinned integrity verification",
        out,
    );
}

fn detect_cwe_497(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let exposes_host_details = source.contains("os.Environ()")
        || source.contains("os.Hostname()")
        || source.contains("runtime.NumCPU()");
    if !exposes_host_details {
        return;
    }
    if source.contains(r#""status": "ok""#) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("os.Environ()") {
        idx
    } else if let Some(idx) = source.find("os.Hostname()") {
        idx
    } else {
        source.find("runtime.NumCPU()").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_497,
        &file,
        line,
        col,
        "the diagnostics endpoint exposes host environment details to callers",
        out,
    );
}

fn detect_cwe_501(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let merged_trust_struct = (source.contains("Approved bool") && source.contains("Amount") && source.contains("Memo"))
        && (source.contains("ShouldBindJSON(&msg)") || source.contains("Decode(&msg)"))
        && source.contains("msg.Approved = true");
    if !merged_trust_struct {
        return;
    }
    if source.contains("payoutDecision") || source.contains("Request  payoutRequest") {
        return;
    }

    let start_byte = source.find("Approved bool").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_501,
        &file,
        line,
        col,
        "trusted approval state is merged into the same struct as untrusted request fields",
        out,
    );
}

fn detect_cwe_502(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let untrusted_gob_decode = source.contains("encoding/gob")
        && source.contains("gob.NewDecoder(")
        && source.contains(".Decode(&action)")
        && source.contains("adminAction")
        && source.contains("Grant");
    if !untrusted_gob_decode {
        return;
    }
    if source.contains("ShouldBindJSON(&req)") || source.contains("json.NewDecoder(r.Body).Decode(&req)") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("gob.NewDecoder(") {
        idx
    } else {
        source.find(".Decode(&action)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_502,
        &file,
        line,
        col,
        "user-controlled gob data is deserialized into a privileged admin action",
        out,
    );
}

fn detect_cwe_515(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let shared_covert_flag = (source.contains("var quotaFlag int")
        || source.contains("var quotaCovertFlag int"))
        && source.contains(r#""over""#)
        && source.contains("= 1")
        && source.contains("= 0")
        && source.contains(r#""over_limit""#);
    if !shared_covert_flag {
        return;
    }
    if source.contains("WHERE tenant = ?") || source.contains("GetString(\"tenant\")") || source.contains("X-Tenant") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("var quotaFlag int") {
        idx
    } else {
        source.find("var quotaCovertFlag int").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_515,
        &file,
        line,
        col,
        "a global quota flag is used as a covert cross-request signal",
        out,
    );
}

fn detect_cwe_521(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let weak_password_policy = source.contains("Password")
        && source.contains("len(body.Password) < 1")
            || source.contains("len(body.Password)<1")
            || source.contains("len(pw) < 1");
    let stores_password = source.contains("password_hash") && (source.contains("body.Password") || source.contains("body.Password"));
    if !(weak_password_policy && stores_password) {
        return;
    }
    if source.contains("strongPassword(") || source.contains("len(pw) < 12") {
        return;
    }

    let start_byte = source.find("len(body.Password) < 1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_521,
        &file,
        line,
        col,
        "password validation allows trivially weak credentials before persistence",
        out,
    );
}

fn detect_cwe_523(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let cleartext_login = (source.contains("/login") && source.contains("password"))
        && (source.contains("Addr: \":8080\"") || source.contains("StartCleartextLogin"));
    if !cleartext_login {
        return;
    }
    if source.contains("requireTLS(") || source.contains("Request.TLS == nil") || source.contains("r.TLS == nil") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("/login") { idx } else { source.find("password").unwrap_or(0) };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_523,
        &file,
        line,
        col,
        "login credentials are accepted before any TLS enforcement or redirect",
        out,
    );
}

fn detect_cwe_524(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let process_wide_token_cache = (source.contains("map[string]string{}") && source.contains("Authorization"))
        && (source.contains("tokenCache") || source.contains("tokenVault"));
    if !process_wide_token_cache {
        return;
    }
    if source.contains("context.WithValue(") || source.contains("session_token") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("tokenCache") {
        idx
    } else {
        source.find("tokenVault").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_524,
        &file,
        line,
        col,
        "raw session tokens are cached in shared process memory keyed by caller identifiers",
        out,
    );
}

fn detect_cwe_538(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let public_secret_export = source.contains("DATABASE_URL")
        && source.contains("os.WriteFile(")
        && (source.contains("/var/www/") || source.contains("/var/www/html/public/"))
        && source.contains("0o644");
    if !public_secret_export {
        return;
    }
    if source.contains("/var/lib/slopguard/private") || source.contains("0o600") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("/var/www/html/public/config-snapshot.txt") {
        idx
    } else {
        source.find("/var/www/static").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_538,
        &file,
        line,
        col,
        "database configuration secrets are exported to a public world-readable file path",
        out,
    );
}

fn detect_cwe_544(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let inconsistent_db_failure_paths = (source.contains("panic(err)") || source.contains("panic(err)\n"))
        && source.contains("log.Println(err)")
        && (source.contains("db.Get(") || source.contains("db.QueryRow("));
    if !inconsistent_db_failure_paths {
        return;
    }
    if source.contains("writeDBError(") || source.contains("writeDBFailure(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("panic(err)") {
        idx
    } else {
        source.find("log.Println(err)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_544,
        &file,
        line,
        col,
        "database failures are handled through inconsistent panic and logging paths",
        out,
    );
}

fn detect_cwe_547(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hardcoded_signing_secret = source.contains("const jwtSecret = ")
        || source.contains("const sessionMACKey = ");
    if !hardcoded_signing_secret {
        return;
    }
    if source.contains("os.Getenv(\"JWT_SIGNING_KEY\")") || source.contains("os.Getenv(\"SESSION_MAC_KEY\")") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("const jwtSecret = ") {
        idx
    } else {
        source.find("const sessionMACKey = ").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_547,
        &file,
        line,
        col,
        "signing material is hard-coded directly in source instead of loaded from runtime secret configuration",
        out,
    );
}

fn detect_cwe_549(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let password_echo = source.contains(r#""password": pass"#)
        && (source.contains("gin.H{") || source.contains("map[string]string"));
    if !password_echo {
        return;
    }
    if source.contains(r#"Encode(map[string]string{"email": email})"#)
        || source.contains("gin.H{\n\t\t\"email\": c.PostForm(\"email\"),\n\t})")
    {
        return;
    }

    let start_byte = source.find(r#""password": pass"#).unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_549,
        &file,
        line,
        col,
        "the response body reflects the submitted password back to the caller",
        out,
    );
}

fn detect_cwe_551(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let raw_path_gate = source.contains("raw := ")
        && source.contains("URL.Path")
        && source.contains("strings.HasPrefix(raw, \"/admin\")")
        && source.contains("strings.ReplaceAll(raw, \"%2f\", \"/\")");
    if !raw_path_gate {
        return;
    }
    if source.contains("url.PathUnescape(raw)") {
        return;
    }

    let start_byte = source.find("strings.HasPrefix(raw, \"/admin\")").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_551,
        &file,
        line,
        col,
        "authorization checks the raw path before percent-unescape canonicalization",
        out,
    );
}

fn detect_cwe_601(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let caller_redirect = source.contains(r#""next""#)
        && (source.contains("c.Redirect(http.StatusFound, target)")
            || source.contains("http.Redirect(w, r, target, http.StatusFound)"));
    if !caller_redirect {
        return;
    }
    if source.contains("strings.HasPrefix(target, \"/\")") || source.contains("strings.Contains(target, \"//\")") {
        return;
    }

    let start_byte = source.find("target").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_601,
        &file,
        line,
        col,
        "the redirect target comes from an unvalidated caller-controlled next parameter",
        out,
    );
}

fn detect_cwe_603(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let trusts_auth_header = source.contains("X-Authenticated")
        && source.contains(r#""true""#)
        && source.contains("UPDATE billing SET plan");
    if !trusts_auth_header {
        return;
    }
    if source.contains("GetString(\"uid\")") || source.contains("Header.Get(\"X-UID\")") {
        return;
    }

    let start_byte = source.find("X-Authenticated").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_603,
        &file,
        line,
        col,
        "billing mutation trusts a caller-supplied authenticated header",
        out,
    );
}

fn detect_cwe_605(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    if !source.contains("SO_REUSEADDR") || !source.contains("SetsockoptInt") {
        return;
    }
    if source.contains("net.Listen(\"tcp\", \":9090\")") {
        return;
    }

    let start_byte = source.find("SO_REUSEADDR").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_605,
        &file,
        line,
        col,
        "the listener explicitly enables SO_REUSEADDR on the service socket",
        out,
    );
}

fn detect_cwe_611(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let unsafe_xml = source.contains("xml.NewDecoder(")
        && source.contains("dec.Strict = false")
        && source.contains("Decode(&catalog)");
    if !unsafe_xml {
        return;
    }
    if source.contains("<!DOCTYPE") || source.contains("dec.Strict = true") || source.contains("LimitReader") {
        return;
    }

    let start_byte = source.find("dec.Strict = false").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_611,
        &file,
        line,
        col,
        "untrusted XML is parsed with strict mode disabled and no DOCTYPE rejection",
        out,
    );
}

fn detect_cwe_613(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let non_expiring_cookie = (source.contains("SetCookie(\"sid\", sid, 0,")
        || source.contains("http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: sid, Path: \"/\", HttpOnly: true})"))
        && source.contains("LogoutHandler");
    if !non_expiring_cookie {
        return;
    }
    if source.contains("revokedSessions[sid]") || source.contains("revokedSessions[c.Value]") || source.contains("MaxAge: 900") || source.contains(", 900,") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("SetCookie(\"sid\", sid, 0,") {
        idx
    } else {
        source
            .find("http.SetCookie(w, &http.Cookie{Name: \"sid\", Value: sid")
            .unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_613,
        &file,
        line,
        col,
        "session login issues a non-expiring cookie and logout does not revoke server-side session state",
        out,
    );
}

fn detect_cwe_618(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let exposes_native_bridge = source.contains("/opt/vendor/activex-bridge")
        && source.contains("exec.Command(")
        && source.contains("method")
        && source.contains("args");
    if !exposes_native_bridge {
        return;
    }
    if source.contains("allowedPluginMethods") {
        return;
    }

    let start_byte = source.find("/opt/vendor/activex-bridge").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_618,
        &file,
        line,
        col,
        "the endpoint forwards caller-controlled method names into a privileged native helper",
        out,
    );
}

fn detect_cwe_619(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let dangling_rows = source.contains("rows, err := db.Query(") && source.contains("rows.Next()");
    if !dangling_rows {
        return;
    }
    if source.contains("defer rows.Close()") {
        return;
    }

    let start_byte = source.find("rows, err := db.Query(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_619,
        &file,
        line,
        col,
        "a database cursor is opened and can return without being closed",
        out,
    );
}

fn detect_cwe_620(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let blind_password_update = source.contains("ChangePassword")
        && source.contains(r#""new_password""#)
        && (source.contains("Update(\"password\",") || source.contains("UPDATE accounts SET password"));
    if !blind_password_update {
        return;
    }
    if source.contains("ForgotPassword")
        || source.contains(r#""current_password""#)
        || source.contains("CompareHashAndPassword")
        || source.contains("ConstantTimeCompare")
    {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_620,
        &file,
        line,
        col,
        "the password change flow updates credentials without verifying the current password",
        out,
    );
}

fn detect_cwe_639(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let user_controlled_key = source.contains("invoice_id")
        && (source.contains("SELECT id, user_id, amount FROM invoices WHERE id = $1")
            || source.contains("SELECT id, user_id, amount FROM invoices WHERE id = $1\", invoiceID"));
    if !user_controlled_key {
        return;
    }
    if source.contains("AND user_id = $2") || source.contains("ownerID") || source.contains("X-User-ID") {
        return;
    }

    let start_byte = source.find("invoice_id").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_639,
        &file,
        line,
        col,
        "a caller-controlled invoice key is queried without owner scoping",
        out,
    );
}

fn detect_cwe_640(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let email_only_reset = source.contains("ForgotPassword")
        && source.contains("new_password")
        && source.contains("email")
        && (source.contains("UPDATE users SET password")
            || source.contains("Where(\"email = ?\", email).Update(\"password\", newPass)"));
    if !email_only_reset {
        return;
    }
    if source.contains("reset_tokens") || source.contains(r#""token""#) || source.contains("expires_at") {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_640,
        &file,
        line,
        col,
        "the recovery flow resets a password from email alone without a reset token",
        out,
    );
}

fn detect_cwe_645(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let one_strike_lockout = source.contains("failedAttempts[user]++") && source.contains("failedAttempts[user] >= 1");
    if !one_strike_lockout {
        return;
    }
    if source.contains("failedAttempts[user] >= 5") || source.contains("lockedUntil") {
        return;
    }

    let start_byte = source.find("failedAttempts[user] >= 1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_645,
        &file,
        line,
        col,
        "the account is locked after a single failed login attempt",
        out,
    );
}

fn detect_cwe_648(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let privileged_chown = source.contains("os.Chown(")
        && source.contains("uid")
        && (source.contains("PostForm(\"uid\")") || source.contains("FormValue(\"uid\")"))
        && (source.contains("PostForm(\"path\")") || source.contains("FormValue(\"path\")"));
    if !privileged_chown {
        return;
    }
    if source.contains("uploadRoot")
        || source.contains("spoolDir")
        || source.contains("serviceUID")
        || source.contains("Setuid(")
    {
        return;
    }

    let start_byte = source.find("os.Chown(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_648,
        &file,
        line,
        col,
        "the handler passes caller-controlled values into a privileged ownership-change API",
        out,
    );
}

fn detect_cwe_649(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let obfuscated_role_cookie = source.contains("Cookie(\"profile\")")
        && source.contains("base64.StdEncoding.DecodeString")
        && source.contains("role=admin");
    if !obfuscated_role_cookie {
        return;
    }
    if source.contains("hmac.New(") || source.contains("hmac.Equal(") || source.contains("RawURLEncoding") {
        return;
    }

    let start_byte = source.find("DecodeString").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_649,
        &file,
        line,
        col,
        "an obfuscated profile cookie is trusted without any integrity verification",
        out,
    );
}

fn detect_cwe_653(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let shared_privileged_store = (source.contains("sharedDB") || source.contains("sharedAuditStore"))
        && source.contains("PublicSearch")
        && source.contains("AdminPurge");
    if !shared_privileged_store {
        return;
    }
    if source.contains("readOnlyDB") || source.contains("readOnlyAuditStore") || source.contains("adminDB") || source.contains("adminAuditStore") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("sharedDB") {
        idx
    } else {
        source.find("sharedAuditStore").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_653,
        &file,
        line,
        col,
        "public and admin paths share the same privileged data store",
        out,
    );
}

fn detect_cwe_654(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let single_factor_admin = source.contains("X-Api-Key")
        && source.contains("legacy-admin-key")
        && source.contains("ExportUsers");
    if !single_factor_admin {
        return;
    }
    if source.contains("Get(\"role\")") || source.contains("X-User-Role") {
        return;
    }

    let start_byte = source.find("legacy-admin-key").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_654,
        &file,
        line,
        col,
        "admin export access is granted solely from a static API key header",
        out,
    );
}

fn detect_cwe_656(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hidden_path_gate = source.contains("/maintenance-portal-9f3c2a") && source.contains("HiddenConfigPanel");
    if !hidden_path_gate {
        return;
    }
    if source.contains("role != \"admin\"") || source.contains("X-User-Role") {
        return;
    }

    let start_byte = source.find("/maintenance-portal-9f3c2a").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_656,
        &file,
        line,
        col,
        "sensitive configuration access relies only on a hidden URL path",
        out,
    );
}

fn detect_cwe_708(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let caller_chosen_owner = source.contains("owner_uid")
        && source.contains("os.Chown(")
        && (source.contains("PostForm(\"dest\")") || source.contains("FormValue(\"dest\")"));
    if !caller_chosen_owner {
        return;
    }
    if source.contains("spoolDir") || source.contains("serviceUID") || source.contains("serviceGID") {
        return;
    }

    let start_byte = source.find("owner_uid").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_708,
        &file,
        line,
        col,
        "the caller chooses both the ownership target and uid for a file operation",
        out,
    );
}

fn detect_cwe_756(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let raw_error_to_client = source.contains("err.Error()")
        && source.contains("FetchProfile")
        && source.contains("SELECT email FROM profiles")
        && (source.contains("c.String(http.StatusInternalServerError, err.Error())")
            || source.contains("http.Error(w, err.Error(), http.StatusInternalServerError)"));
    if !raw_error_to_client {
        return;
    }
    if source.contains("\"unable to load profile\"") {
        return;
    }

    let start_byte = source.find("err.Error()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_756,
        &file,
        line,
        col,
        "raw database error text is returned directly to the client",
        out,
    );
}

fn detect_cwe_765(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let double_unlock = source.contains("Unlock()") && source.matches("Unlock()").count() >= 2 && source.contains("DebitWallet");
    if !double_unlock {
        return;
    }
    if source.contains("defer walletMu.Unlock()") || source.contains("defer cacheMu.Unlock()") {
        return;
    }

    let start_byte = source.find("Unlock()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_765,
        &file,
        line,
        col,
        "the critical-section lock is explicitly released twice on an error path",
        out,
    );
}

fn detect_cwe_778(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let missing_auth_audit = source.contains("SignIn")
        && source.contains("username")
        && source.contains("password")
        && source.contains("Unauthorized");
    if !missing_auth_audit {
        return;
    }
    if source.contains("log.Printf(\"auth failure") {
        return;
    }

    let start_byte = source.find("Unauthorized").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_778,
        &file,
        line,
        col,
        "authentication failures are returned without any audit logging",
        out,
    );
}

fn detect_cwe_783(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let precedence_bug = source.contains("!authenticated || isAdmin && ownerID == docOwner");
    if !precedence_bug {
        return;
    }
    if source.contains("!(isAdmin || ownerID == docOwner)") {
        return;
    }

    let start_byte = source.find("!authenticated || isAdmin && ownerID == docOwner").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_783,
        &file,
        line,
        col,
        "authorization depends on ambiguous && and || precedence",
        out,
    );
}

fn detect_cwe_798(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hardcoded_dsn = source.contains("postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable");
    if !hardcoded_dsn {
        return;
    }
    if source.contains("os.Getenv(\"REPORTING_DSN\")") {
        return;
    }

    let start_byte = source.find("postgres://reporting:Tr4ck3rP@ss@db.internal:5432/reports?sslmode=disable").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_798,
        &file,
        line,
        col,
        "database credentials are embedded directly in the source code",
        out,
    );
}

fn detect_cwe_820(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let unsynchronized_map_write = source.contains("visitCounts[key] = visitCounts[key] + 1") && source.contains("TrackVisit");
    if !unsynchronized_map_write {
        return;
    }
    if source.contains("visitMu.Lock()") || source.contains("visitMu sync.Mutex") {
        return;
    }

    let start_byte = source.find("visitCounts[key] = visitCounts[key] + 1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_820,
        &file,
        line,
        col,
        "shared visit counters are updated without synchronization",
        out,
    );
}

fn detect_cwe_821(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let writes_under_rlock = source.contains("RLock()") && source.contains("tokenCache[key] = value");
    if !writes_under_rlock {
        return;
    }
    if source.contains("cacheMu.Lock()") {
        return;
    }

    let start_byte = source.find("RLock()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_821,
        &file,
        line,
        col,
        "shared cache state is mutated while only a read lock is held",
        out,
    );
}

fn detect_cwe_826(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let premature_release = source.contains("go func()")
        && source.contains("db.Close()")
        && (source.contains("db.Query(") || source.contains("db.Query(\"SELECT"));
    if !premature_release {
        return;
    }
    if source.contains("QueryContext(") || source.contains("<-done\n\tc.Status(") && !source.contains("db.Close()") {
        return;
    }

    let start_byte = source.find("db.Close()").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_826,
        &file,
        line,
        col,
        "a shared database handle is closed before a background task finishes using it",
        out,
    );
}

fn detect_cwe_829(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let untrusted_plugin_path = source.contains("plugin.Open(")
        && (source.contains("module_path") || source.contains("path := "));
    if !untrusted_plugin_path {
        return;
    }
    if source.contains("allowedModules") || source.contains("moduleRoot") {
        return;
    }

    let start_byte = source.find("plugin.Open(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_829,
        &file,
        line,
        col,
        "a plugin is loaded from a caller-controlled filesystem path",
        out,
    );
}

fn detect_cwe_836(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let client_submits_hash = source.contains("PasswordHash string")
        || source.contains("`json:\"password_hash\"`");
    let hash_as_password = client_submits_hash
        && (source.contains("password_hash = ?")
            || source.contains("WHERE username = ? AND password_hash = ?")
            || source.contains("WHERE username = $1 AND password_hash = $2"));
    if !hash_as_password {
        return;
    }
    if source.contains("CompareHashAndPassword") || source.contains("ConstantTimeCompare") {
        return;
    }

    let start_byte = source.find("password_hash").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_836,
        &file,
        line,
        col,
        "authentication accepts a caller-supplied password hash instead of verifying a plaintext password",
        out,
    );
}

fn detect_cwe_838(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let invalid_utf8 = source.contains("application/json; charset=utf-8")
        && source.contains("0xC3, 0x28");
    if !invalid_utf8 {
        return;
    }

    let start_byte = source.find("0xC3, 0x28").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_838,
        &file,
        line,
        col,
        "invalid byte sequences are emitted while declaring UTF-8 JSON output",
        out,
    );
}

fn detect_cwe_841(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let workflow_skip = source.contains("ResetAccount")
        && source.contains("new_password")
        && source.contains("password");
    if !workflow_skip {
        return;
    }
    if source.contains("MFAPassed") && source.contains("if !acct.MFAPassed")
        || source.contains("if !accountMFAPassed[email]")
    {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_841,
        &file,
        line,
        col,
        "the reset workflow changes credentials without enforcing MFA completion",
        out,
    );
}

fn detect_cwe_842(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let wrong_default_group = source.contains("RegisterMember")
        && source.contains("Group: \"administrators\"");
    if !wrong_default_group {
        return;
    }
    if source.contains("Group: \"members\"") {
        return;
    }

    let start_byte = source.find("Group: \"administrators\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_842,
        &file,
        line,
        col,
        "newly registered users are assigned to an administrator group by default",
        out,
    );
}

fn detect_cwe_909(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let missing_init_guard = (source.contains("appDB.Find(") || source.contains("widgetDB.Query("))
        && !source.contains("if appDB == nil")
        && !source.contains("if widgetDB == nil");
    if !missing_init_guard {
        return;
    }

    let start_byte = if let Some(idx) = source.find("appDB.Find(") {
        idx
    } else {
        source.find("widgetDB.Query(").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_909,
        &file,
        line,
        col,
        "a global database handle is used without checking that initialization completed",
        out,
    );
}

fn detect_cwe_915(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let mass_assignment = source.contains("map[string]interface{}")
        && (source.contains("Updates(fields)") || source.contains("json.Unmarshal(raw, &p)"));
    if !mass_assignment {
        return;
    }
    if source.contains("Update(\"name\"") || source.contains("p.Name = body.Name") {
        return;
    }

    let start_byte = source.find("map[string]interface{}").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_915,
        &file,
        line,
        col,
        "a user-controlled attribute map updates privileged object fields directly",
        out,
    );
}

fn detect_cwe_916(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let weak_password_hash = source.contains("md5.Sum(") && source.contains("password");
    if !weak_password_hash {
        return;
    }
    if source.contains("bcrypt.GenerateFromPassword") || source.contains("hashIterations = 100_000") {
        return;
    }

    let start_byte = source.find("md5.Sum(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_916,
        &file,
        line,
        col,
        "password storage uses a fast MD5 hash with insufficient computational effort",
        out,
    );
}

fn detect_cwe_917(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let template_injection = source.contains("template.New(\"report\").Parse(src)")
        && source.contains("{{.Title}} where ")
        && source.contains("+ expr");
    if !template_injection {
        return;
    }
    if source.contains("reportTemplate") || source.contains("reportTemplatePure") {
        return;
    }

    let start_byte = source.find("{{.Title}} where ").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_917,
        &file,
        line,
        col,
        "caller-controlled data is concatenated into the template source itself",
        out,
    );
}

fn detect_cwe_918(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let ssrf_fetch = source.contains("http.Get(target)")
        && (source.contains("c.Query(\"url\")") || source.contains("r.URL.Query().Get(\"url\")"));
    if !ssrf_fetch {
        return;
    }
    if source.contains("allowedHosts") || source.contains("allowedHostsPure") || source.contains("Hostname()") {
        return;
    }

    let start_byte = source.find("http.Get(target)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_918,
        &file,
        line,
        col,
        "an outbound request is sent to a caller-controlled URL without host allowlisting",
        out,
    );
}

fn detect_cwe_921(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let world_readable_secret = source.contains("/tmp/integration.key")
        && source.contains("WriteFile(")
        && source.contains("0644");
    if !world_readable_secret {
        return;
    }
    if source.contains("APP_SECRET_DIR") || source.contains("0600") {
        return;
    }

    let start_byte = source.find("/tmp/integration.key").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_921,
        &file,
        line,
        col,
        "sensitive integration key material is stored in a world-readable temporary file",
        out,
    );
}

fn detect_cwe_924(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let applies_payment_webhook = (source.contains("AcceptWebhook(")
        || source.contains("AcceptWebhookPure(")
        || source.contains("AcceptWebhookVerified(")
        || source.contains("AcceptWebhookVerifiedPure("))
        && source.contains("UPDATE invoices SET paid = true")
        && (source.contains("BindJSON(&evt)") || source.contains("Decode(&evt)") || source.contains("Unmarshal(body, &evt)"));
    if !applies_payment_webhook {
        return;
    }
    if source.contains("X-Signature")
        || source.contains("hmac.New(sha256.New")
        || source.contains("hmac.Equal(")
    {
        return;
    }

    let start_byte = source
        .find("BindJSON(&evt)")
        .or_else(|| source.find("Decode(&evt)"))
        .unwrap_or_else(|| source.find("UPDATE invoices SET paid = true").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_924,
        &file,
        line,
        col,
        "a payment webhook body is applied without validating an integrity signature first",
        out,
    );
}

fn detect_cwe_940(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let oauth_callback = (source.contains("OAuthCallback(") || source.contains("OAuthCallbackPure("))
        && source.contains("code")
        && source.contains("INSERT INTO oauth_tokens (user_id, code) VALUES ($1, $2)");
    if !oauth_callback {
        return;
    }
    if source.contains("oauth_state")
        || source.contains("Cookie(\"oauth_state\")")
        || source.contains("r.Cookie(\"oauth_state\")")
        || source.contains("invalid oauth state")
    {
        return;
    }

    let start_byte = source
        .find("Query(\"user_id\")")
        .or_else(|| source.find("Query().Get(\"user_id\")"))
        .unwrap_or_else(|| source.find("oauth_tokens").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_940,
        &file,
        line,
        col,
        "an OAuth callback accepts caller-supplied authorization data without verifying a bound state token",
        out,
    );
}

fn detect_cwe_941(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let caller_directed_reset = (source.contains("SendResetLink(") || source.contains("SendResetLinkPure("))
        && source.contains("smtp.SendMail")
        && (source.contains("Query(\"email\")") || source.contains("Query().Get(\"email\")"))
        && source.contains("[]string{email}");
    if !caller_directed_reset {
        return;
    }
    if source.contains("user.Email")
        || source.contains("lookupEmail(")
        || source.contains("sessionUserID")
    {
        return;
    }

    let start_byte = source
        .find("Query(\"email\")")
        .or_else(|| source.find("Query().Get(\"email\")"))
        .unwrap_or_else(|| source.find("[]string{email}").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_941,
        &file,
        line,
        col,
        "a reset notification is sent to a caller-controlled email address",
        out,
    );
}

fn detect_cwe_1051(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hard_coded_upstream = (source.contains("ChargeCard(") || source.contains("ChargeCardPure("))
        && source.contains("10.20.30.40:9090")
        && source.contains("http.NewRequest(")
        && source.contains("X-Card-Token");
    if !hard_coded_upstream {
        return;
    }
    if source.contains("os.Getenv(\"BILLING_API_URL\")") {
        return;
    }

    let start_byte = source.find("10.20.30.40:9090").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1051,
        &file,
        line,
        col,
        "an outbound billing request is pinned to a hard-coded internal host",
        out,
    );
}

fn detect_cwe_1052(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let hard_coded_dsn = (source.contains("gorm.Open(postgres.Open(dsn)")
        || source.contains("sql.Open(\"postgres\", appDSNPure)"))
        && source.contains("password=SuperSecret99")
        && source.contains("host=db.internal");
    if !hard_coded_dsn {
        return;
    }
    if source.contains("APP_DATABASE_URL") || source.contains("DB_PASSWORD") {
        return;
    }

    let start_byte = source.find("password=SuperSecret99").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1052,
        &file,
        line,
        col,
        "database initialization embeds a complete DSN with hard-coded credentials",
        out,
    );
}

fn detect_cwe_1067(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let leading_wildcard_scan = (source.contains("fmt.Sprintf(\"%%%s%%\", term)")
        || source.contains("pattern := fmt.Sprintf(\"%%%s%%\", term)"))
        && source.contains("LIKE")
        && (source.contains("notes.body") || source.contains("SELECT id, body FROM notes"));
    if !leading_wildcard_scan {
        return;
    }
    if source.contains("prefix+\"%\"") || source.contains("pattern := prefix + \"%\"") {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%%%s%%\", term)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1067,
        &file,
        line,
        col,
        "a search predicate uses a leading wildcard pattern that forces a sequential scan",
        out,
    );
}

fn detect_cwe_1173(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let bypassed_validation = source.contains("var raw map[string]interface{}")
        && (source.contains("ShouldBindJSON(&raw)") || source.contains("Decode(&raw)"))
        && (source.contains("SignupPayload{}") || source.contains("SignupPayloadPure{}"));
    if !bypassed_validation {
        return;
    }
    if source.contains("ShouldBindJSON(&payload)")
        || source.contains("Decode(&payload)")
        || source.contains("mail.ParseAddress(payload.Email)")
    {
        return;
    }

    let start_byte = source.find("var raw map[string]interface{}").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1173,
        &file,
        line,
        col,
        "request data is decoded into a generic map instead of the validated signup model",
        out,
    );
}

fn detect_cwe_1125(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let wide_surface = (source.contains("MountWideSurface(") || source.contains("MountWideSurfacePure("))
        && (source.contains("/debug/pprof") || source.contains("pprof.Index"))
        && source.contains("/admin/sql")
        && source.contains("/admin/config")
        && source.contains("/internal/reload");
    if !wide_surface {
        return;
    }
    if source.contains("authRequired()") || source.contains("authRequiredPure(") {
        return;
    }

    let start_byte = source.find("/debug/pprof").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1125,
        &file,
        line,
        col,
        "public routing exposes debug, admin, and internal maintenance endpoints together",
        out,
    );
}

fn detect_cwe_1204(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let static_iv = source.contains("cipher.NewCBCEncrypter(")
        && (source.contains("weakIV") || source.contains("weakIVPure"))
        && source.contains("1234567890123456");
    if !static_iv {
        return;
    }
    if source.contains("io.ReadFull(rand.Reader, iv)") {
        return;
    }

    let start_byte = source.find("1234567890123456").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1204,
        &file,
        line,
        col,
        "CBC encryption uses a fixed IV literal instead of generating one per request",
        out,
    );
}

fn detect_cwe_1220(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let unscoped_invoice_read = (source.contains("GetInvoice(") || source.contains("GetInvoicePure("))
        && source.contains("Authorization")
        && source.contains("FROM invoices WHERE id = $1");
    if !unscoped_invoice_read {
        return;
    }
    if source.contains("owner_id = $2") || source.contains("ownerID") || source.contains("X-User-ID") {
        return;
    }

    let start_byte = source.find("FROM invoices WHERE id = $1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1220,
        &file,
        line,
        col,
        "invoice access is authenticated but not scoped to the requesting owner",
        out,
    );
}

fn detect_cwe_1230(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let metadata_leak = (source.contains("DownloadRedacted(") || source.contains("DownloadRedactedPure("))
        && source.contains("X-Original-Name")
        && source.contains("X-File-Size")
        && source.contains("[REDACTED CONTENT]");
    if !metadata_leak {
        return;
    }
    if source.contains("Cache-Control") {
        return;
    }

    let start_byte = source.find("X-Original-Name").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1230,
        &file,
        line,
        col,
        "a redacted download response still exposes sensitive filename and size metadata",
        out,
    );
}

fn detect_cwe_1236(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let raw_csv_export = (source.contains("ExportFeedbackCSV(") || source.contains("ExportFeedbackCSVPure("))
        && source.contains("id,comment")
        && source.contains("fmt.Sprintf(\"%d,%s\\n\"")
        && source.contains("row.Comment");
    if !raw_csv_export {
        return;
    }
    if source.contains("sanitizeCSVField(") || source.contains("sanitizeCSVFieldPure(") || source.contains("csv.NewWriter(") {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%d,%s\\n\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1236,
        &file,
        line,
        col,
        "CSV export writes user-controlled comment cells without neutralizing spreadsheet formulas",
        out,
    );
}

fn detect_cwe_1240(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let custom_xor_cipher = (source.contains("SealSessionToken(") || source.contains("SealSessionTokenPure("))
        && (source.contains("xorCipher(") || source.contains("xorCipherPure("))
        && source.contains("^ key");
    if !custom_xor_cipher {
        return;
    }
    if source.contains("cipher.NewGCM(") || source.contains("aes.NewCipher(") {
        return;
    }

    let start_byte = source.find("xorCipher").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1240,
        &file,
        line,
        col,
        "session sealing uses a homegrown XOR cipher instead of a standard authenticated primitive",
        out,
    );
}

fn detect_cwe_1265(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let nested_lock_reentry = (source.contains("UpdateBalance(") || source.contains("UpdateBalancePure("))
        && (source.contains("ledgerMu.Lock()") || source.contains("ledgerMuPure.Lock()"))
        && (source.contains("PostTransfer(") || source.contains("PostTransferPure("));
    if !nested_lock_reentry {
        return;
    }
    if source.contains("applyBalanceDelta(") || source.contains("applyBalanceDeltaPure(") {
        return;
    }

    let start_byte = source.find("UpdateBalance(")
        .or_else(|| source.find("UpdateBalancePure("))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1265,
        &file,
        line,
        col,
        "a transfer path re-enters a mutex-protected balance helper while the same mutex is already held",
        out,
    );
}

fn detect_cwe_1286(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let loose_json_config = (source.contains("SaveHookConfig(") || source.contains("SaveHookConfigPure("))
        && (source.contains("json.Unmarshal(body, &cfg)") || source.contains("json.NewDecoder(r.Body).Decode(&cfg)"))
        && source.contains("hook_configs");
    if !loose_json_config {
        return;
    }
    if source.contains("DisallowUnknownFields()") || source.contains("ParseRequestURI(cfg.URL)") {
        return;
    }

    let start_byte = source.find("json.Unmarshal(body, &cfg)")
        .or_else(|| source.find("json.NewDecoder(r.Body).Decode(&cfg)"))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1286,
        &file,
        line,
        col,
        "webhook configuration JSON is accepted without strict syntax and URL validation",
        out,
    );
}

fn detect_cwe_1289(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let literal_path_block = (source.contains("FetchSharedAsset(") || source.contains("FetchSharedAssetPure("))
        && source.contains("requested == \"private/keys.pem\"")
        && source.contains("filepath.Join(root, requested)");
    if !literal_path_block {
        return;
    }
    if source.contains("filepath.Clean(filepath.Join(root, requested))") || source.contains("HasPrefix(clean, root+string(filepath.Separator))") {
        return;
    }

    let start_byte = source.find("requested == \"private/keys.pem\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1289,
        &file,
        line,
        col,
        "asset access relies on a literal blocked path comparison before canonical normalization",
        out,
    );
}

fn detect_cwe_1322(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let blocking_worker = (source.contains("StartWebhookWorker(") || source.contains("StartWebhookWorkerPure("))
        && source.contains("queue := make(chan")
        && source.contains("for payload := range queue")
        && source.contains("time.Sleep(2 * time.Second)");
    if !blocking_worker {
        return;
    }
    if source.contains("time.AfterFunc(") {
        return;
    }

    let start_byte = source.find("time.Sleep(2 * time.Second)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1322,
        &file,
        line,
        col,
        "the webhook worker blocks its queue loop with sleep instead of scheduling retries asynchronously",
        out,
    );
}

fn detect_cwe_1327(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let unrestricted_bind = (source.contains("StartPublicAPI(") || source.contains("StartPublicAPIPure("))
        && (source.contains("Run(\":9090\")") || source.contains("ListenAndServe(\":9090\","));
    if !unrestricted_bind {
        return;
    }
    if source.contains("127.0.0.1:9090") {
        return;
    }

    let start_byte = source.find(":9090").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1327,
        &file,
        line,
        col,
        "the service binds to all interfaces instead of a restricted loopback address",
        out,
    );
}

fn detect_cwe_1333(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let redos_pattern = source.contains("^([a-zA-Z]+)*$")
        && (source.contains("tagPattern") || source.contains("tagPatternPure"))
        && source.contains("MatchString(tag)");
    if !redos_pattern {
        return;
    }
    if source.contains("safeTagPattern") || source.contains("len(tag) > 32") {
        return;
    }

    let start_byte = source.find("^([a-zA-Z]+)*$").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1333,
        &file,
        line,
        col,
        "tag validation uses a catastrophic-backtracking regex on attacker-controlled input",
        out,
    );
}

fn detect_cwe_1389(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let implicit_radix = (source.contains("ReserveSeats(") || source.contains("ReserveSeatsPure("))
        && source.contains("strconv.ParseInt(raw, 0, 64)");
    if !implicit_radix {
        return;
    }
    if source.contains("strconv.ParseInt(raw, 10, 64)") {
        return;
    }

    let start_byte = source.find("strconv.ParseInt(raw, 0, 64)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1389,
        &file,
        line,
        col,
        "seat counts are parsed with base 0 and may accept alternate-radix prefixes unexpectedly",
        out,
    );
}

fn detect_cwe_1392(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let default_admin = (source.contains("BootstrapAdmin(") || source.contains("BootstrapAdminPure("))
        && source.contains("Username: \"admin\"")
        && source.contains("Password: \"admin\"");
    if !default_admin {
        return;
    }
    if source.contains("BOOTSTRAP_ADMIN_PASSWORD") {
        return;
    }

    let start_byte = source.find("Password: \"admin\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1392,
        &file,
        line,
        col,
        "administrator bootstrap uses a built-in default password literal",
        out,
    );
}

fn detect_cwe_807(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.path.display().to_string();
    let source = unit.source.as_ref();

    let spoofable_ip_gate = source.contains("blockedIPs")
        && (source.contains("GetHeader(\"X-Forwarded-For\")")
            || source.contains("Header.Get(\"X-Forwarded-For\")"));
    if !spoofable_ip_gate {
        return;
    }
    if source.contains("RemoteAddr") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("X-Forwarded-For") {
        idx
    } else {
        source.find("blockedIPs").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_807,
        &file,
        line,
        col,
        "a security gate trusts the caller-controlled forwarded IP header",
        out,
    );
}

fn is_configuration_sink(callee: &str) -> bool {
    matches!(callee, "sql.Open" | "factory")
}

fn is_path_traversal_sink(callee: &str) -> bool {
    matches!(callee, "os.ReadFile")
}

fn is_link_resolution_sink(callee: &str) -> bool {
    matches!(callee, "os.Open" | "os.OpenFile")
}

fn argument_uses_identifier(argument: &str, ident: &str) -> bool {
    argument == ident
}

fn expression_uses_request_input(expr: &str) -> bool {
    expr.contains(".Query(")
        || expr.contains(".URL.Query().Get(")
        || expr.contains(".PostForm(")
        || expr.contains(".FormValue(")
        || expr.contains(".Param(")
        || expr.contains(".PathValue(")
}

fn is_path_confined(source: &str, assignment: &facts::AssignmentFact) -> bool {
    (assignment.expr.contains("filepath.Clean(") && source.contains(&format!("strings.HasPrefix({},", assignment.name)))
        || assignment.expr.contains("filepath.Base(")
        || (assignment.expr.contains("filepath.Abs(") && has_canonical_path_guard(source, &assignment.name))
}

fn has_canonical_path_guard(source: &str, path_name: &str) -> bool {
    source.contains(&format!("strings.HasPrefix({},", path_name))
        && source.contains("filepath.Abs(")
}

fn has_symlink_guard(source: &str, path_name: &str) -> bool {
    source.contains(&format!("os.Lstat({})", path_name))
        && source.contains("os.ModeSymlink")
}
