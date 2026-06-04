//! Bundled Go CWE heuristics.

mod facts;

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{emit, Finding, Rule, RuleMetadata, Severity};

use self::facts::{build_go_unit_facts, GoUnitFacts, InputKind};

pub struct GoCweScan;

const GO_CWE_RULE_IDS: &[&str] = &["CWE-15", "CWE-22", "CWE-41", "CWE-59", "CWE-76", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-112", "CWE-140", "CWE-178", "CWE-179", "CWE-182", "CWE-184", "CWE-186", "CWE-201", "CWE-204", "CWE-208", "CWE-209", "CWE-212", "CWE-213", "CWE-214", "CWE-215", "CWE-250", "CWE-252", "CWE-256", "CWE-257", "CWE-260", "CWE-261", "CWE-262", "CWE-263", "CWE-266", "CWE-267", "CWE-268", "CWE-270", "CWE-272", "CWE-273", "CWE-274", "CWE-276", "CWE-277", "CWE-278", "CWE-279", "CWE-280", "CWE-281", "CWE-283", "CWE-289", "CWE-290"];

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
