//! Rule maturity tags for catalog honesty and pack membership.

/// How trustworthy / general a rule is for production CI packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMaturity {
    /// Graph-based injection/XSS family (taint).
    TaintCore,
    /// AST/facts with generalized patterns.
    Structural,
    /// Useful smell, higher FP rate.
    Heuristic,
    /// Encodes test corpus strings; never in recommended/security.
    FixtureOnly,
    /// Placeholder / reserved; disabled outside `all`.
    Reserved,
}

impl RuleMaturity {
    /// Stable string tag for this maturity level (e.g. `taint-core`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TaintCore => "taint-core",
            Self::Structural => "structural",
            Self::Heuristic => "heuristic",
            Self::FixtureOnly => "fixture-only",
            Self::Reserved => "reserved",
        }
    }

    /// Allowed in recommended or security packs.
    pub fn allowed_in_default_packs(self) -> bool {
        matches!(self, Self::TaintCore | Self::Structural | Self::Heuristic)
    }
}

/// Look up maturity for a rule ID. Unknown rules default to [`RuleMaturity::Heuristic`].
pub fn maturity_for(rule_id: &str) -> RuleMaturity {
    if is_fixture_only(rule_id) {
        return RuleMaturity::FixtureOnly;
    }
    if is_reserved(rule_id) {
        return RuleMaturity::Reserved;
    }
    if is_taint_core(rule_id) {
        return RuleMaturity::TaintCore;
    }
    if is_structural_cwe(rule_id) {
        return RuleMaturity::Structural;
    }
    RuleMaturity::Heuristic
}

/// True if this rule must never appear in recommended/security packs.
pub fn is_quarantined_from_default_packs(rule_id: &str) -> bool {
    !maturity_for(rule_id).allowed_in_default_packs()
}

fn is_taint_core(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "CWE-22" | "CWE-78" | "CWE-79" | "CWE-89" | "CWE-90" | "CWE-91"
    )
}

fn is_structural_cwe(rule_id: &str) -> bool {
    // Structural eligibility is deliberately an explicit allow-list. Do not add
    // a rule without satisfying the promotion bar in the CWE catalog trust audit.
    matches!(
        rule_id,
        "CWE-41" | "CWE-59" | "CWE-76" | "CWE-93" | "CWE-112" | "CWE-22"
    )
}

/// Rules audited as fixture-only: their current evidence is a corpus literal,
/// magic value, or project-specific identifier rather than a generalized fact.
/// Keep sorted for review; see `plans/v0.0.5/cwe-catalog-trust-audit.md`.
fn is_fixture_only(rule_id: &str) -> bool {
    matches!(
        rule_id,
        // PRNG / token fixture museum (see domains/cryptography/prng.rs)
        "CWE-334"
            | "CWE-335"
            | "CWE-338"
            | "CWE-342"
            | "CWE-343"
            // Cipher long-tail museum (see domains/cryptography/ciphers.rs)
            // CWE-325 stays Heuristic: call-facts primary after §2.3 rewrite,
            // but not structural-promoted (no §1.3 real-module bar yet).
            | "CWE-1204" // fixed IV literal + weakIV identifiers
            | "CWE-1240" // SealSessionToken / xorCipher corpus helpers
            // Crypto-strength / JWT long-tail museum (Tranche 3 / §2.4)
            // CWE-328 stays Heuristic: call-facts primary (md5.Sum) after §2.3;
            // production-shaped and real-module hits, not structural-promoted.
            | "CWE-323" // fixed nonce identifiers + fixednonce12 literals
            | "CWE-331" // Intn(900000)+100000 recovery-code fixture bound
            | "CWE-347" // JWT manual split/decode without verify (exact names)
            // OAuth / authorization-bypass long-tail museum (Tranche 4 / §2.5)
            // CWE-941 uses call_facts primary for smtp.SendMail after §2.5 rewrite,
            // but still requires SendResetLink helper names + exact recipient slice.
            | "CWE-940" // OAuthCallback helpers + oauth_tokens INSERT corpus shape
            | "CWE-941" // SendResetLink helpers + Query("email") + []string{email}
            // File/path upload long-tail (Tranche 5 / §2.6)
            | "CWE-434" // client filename + /var/www/static/avatars corpus paths
            // Network binding museum (Tranche 5 / §2.7)
            | "CWE-1327" // StartPublicAPI helpers + :9090 bind corpus shape
            // Permissions chown museum (Tranche 5 / §2.9)
            // CWE-648/708 use call_facts primary for os.Chown after §2.9 rewrite,
            // but still require FormValue uid/path / owner_uid + dest corpus co-signals.
            | "CWE-648" // FormValue/PostForm("uid")+("path") + os.Chown corpus shape
            | "CWE-708" // owner_uid + FormValue/PostForm("dest") + os.Chown corpus shape
            // Transport TLS + JWT neighbor museum (Tranche 5 / §2.10)
            // CWE-319 uses call_facts primary for ListenAndServe after §2.10 rewrite,
            // but still requires CVV + Number payment-field corpus co-signals.
            | "CWE-319" // card CVV/Number + cleartext ListenAndServe corpus shape
            | "CWE-358" // Bearer trim + JWT middle-segment decode without structure/alg checks
            // File-mode permissions long-tail (long-tail §2.11 under #45)
            // CWE-250 stays Heuristic: call-facts primary for os.WriteFile + 0o777;
            // production-shaped world-writable mode, not structural-promoted.
            // CWE-552 uses call_facts primary for os.Chmod after §2.11 rewrite,
            // but still requires FormFile("contract") + /srv/contracts corpus co-signals.
            | "CWE-252" // unchecked WriteFile gated on exact /var/log audit|journal paths
            | "CWE-552" // FormFile("contract") + /srv/contracts + os.Chmod 0o777 corpus shape
            // Access-control file-permissions siblings (Phase 2 / #87)
            // CWE-277 stays Heuristic: generalized call_facts Umask(0)+MkdirAll(0777);
            // production-shaped, not structural-promoted (no §1.3 real-module bar yet).
            | "CWE-276" // WriteFile 0666 + sessions/session_data/X-Session-Data co-signals
            | "CWE-278" // OpenFile mode arg exact os.FileMode(hdr.Mode) corpus formula
            | "CWE-279" // ParseUint co-presence + WriteFile 0777 (no mode dataflow)
            | "CWE-281" // os.Create + exact io.Copy(out, in) + !info.Mode() corpus shape
            | "CWE-921" // /tmp/integration.key + WriteFile 0644 corpus path/mode
            // Parallel catalog batch 1 / epic #95 (A1–A4)
            // CWE-916 stays Heuristic: call_facts md5.Sum + password co-signal;
            // real-module gopdfsuit PDF password MD5 hits; not structural-promoted.
            | "CWE-256" // exact GORM/SQL plaintext password persistence corpus
            | "CWE-257" // AES-GCM+base64 chain gated on password:encoded persistence
            | "CWE-261" // base64 encode gated on Secret:encoded / Store(user, encoded)
            | "CWE-524" // tokenCache/tokenVault + Authorization process-wide map
            | "CWE-538" // DATABASE_URL WriteFile 0o644 + /var/www public path corpus
            | "CWE-502" // gob.NewDecoder + adminAction/Grant + Decode(&action) corpus
            | "CWE-425" // /internal/admin/export.csv + PII SELECT without requireAdmin
            | "CWE-551" // raw path HasPrefix/ReplaceAll client-side filter corpus
            | "CWE-653" // sharedDB/sharedAuditStore + PublicSearch/AdminPurge
            | "CWE-639" // invoice_id unscoped invoice SELECT corpus
            | "CWE-1220" // GetInvoice* + Authorization + unscoped SQL corpus
            // Common fixture-shaped long-tail (path/corpus strings)
            | "CWE-798" // hard-coded credentials often fixture-shaped
    )
}

fn is_reserved(rule_id: &str) -> bool {
    // BP-63 is a curated advisory *snapshot*, not a live govulncheck feed.
    // Keep it out of recommended/security until a real vulnerability feed
    // is wired. BP-64/65 have real project-level detectors and are not reserved.
    matches!(rule_id, "BP-63")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_only_quarantined() {
        assert_eq!(maturity_for("CWE-334"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-1204"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-1240"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-323"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-331"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-347"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-940"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-941"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-434"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-1327"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-648"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-708"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-319"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-358"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-252"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-552"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-276"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-278"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-279"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-281"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-921"), RuleMaturity::FixtureOnly);
        // Parallel catalog batch 1 (epic #95)
        assert_eq!(maturity_for("CWE-256"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-257"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-261"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-524"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-538"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-502"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-425"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-551"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-653"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-639"), RuleMaturity::FixtureOnly);
        assert_eq!(maturity_for("CWE-1220"), RuleMaturity::FixtureOnly);
        // Cipher / weak-hash / world-writable WriteFile / umask+mkdir / password MD5 smells remain heuristic
        // (call-facts primary for 325/328/250/277/916; not structural-promoted).
        assert_eq!(maturity_for("CWE-325"), RuleMaturity::Heuristic);
        assert_eq!(maturity_for("CWE-328"), RuleMaturity::Heuristic);
        assert_eq!(maturity_for("CWE-250"), RuleMaturity::Heuristic);
        assert_eq!(maturity_for("CWE-277"), RuleMaturity::Heuristic);
        assert_eq!(maturity_for("CWE-916"), RuleMaturity::Heuristic);
        assert!(is_quarantined_from_default_packs("CWE-334"));
        assert!(is_quarantined_from_default_packs("CWE-1204"));
        assert!(is_quarantined_from_default_packs("CWE-323"));
        assert!(is_quarantined_from_default_packs("CWE-331"));
        assert!(is_quarantined_from_default_packs("CWE-347"));
        assert!(is_quarantined_from_default_packs("CWE-940"));
        assert!(is_quarantined_from_default_packs("CWE-941"));
        assert!(is_quarantined_from_default_packs("CWE-434"));
        assert!(is_quarantined_from_default_packs("CWE-1327"));
        assert!(is_quarantined_from_default_packs("CWE-648"));
        assert!(is_quarantined_from_default_packs("CWE-708"));
        assert!(is_quarantined_from_default_packs("CWE-319"));
        assert!(is_quarantined_from_default_packs("CWE-358"));
        assert!(is_quarantined_from_default_packs("CWE-252"));
        assert!(is_quarantined_from_default_packs("CWE-552"));
        assert!(is_quarantined_from_default_packs("CWE-276"));
        assert!(is_quarantined_from_default_packs("CWE-278"));
        assert!(is_quarantined_from_default_packs("CWE-279"));
        assert!(is_quarantined_from_default_packs("CWE-281"));
        assert!(is_quarantined_from_default_packs("CWE-921"));
        assert!(is_quarantined_from_default_packs("CWE-256"));
        assert!(is_quarantined_from_default_packs("CWE-257"));
        assert!(is_quarantined_from_default_packs("CWE-261"));
        assert!(is_quarantined_from_default_packs("CWE-524"));
        assert!(is_quarantined_from_default_packs("CWE-538"));
        assert!(is_quarantined_from_default_packs("CWE-502"));
        assert!(is_quarantined_from_default_packs("CWE-425"));
        assert!(is_quarantined_from_default_packs("CWE-551"));
        assert!(is_quarantined_from_default_packs("CWE-653"));
        assert!(is_quarantined_from_default_packs("CWE-639"));
        assert!(is_quarantined_from_default_packs("CWE-1220"));
        assert!(!is_quarantined_from_default_packs("CWE-325"));
        assert!(!is_quarantined_from_default_packs("CWE-328"));
        assert!(!is_quarantined_from_default_packs("CWE-250"));
        assert!(!is_quarantined_from_default_packs("CWE-277"));
        assert!(!is_quarantined_from_default_packs("CWE-916"));
        assert!(!is_quarantined_from_default_packs("CWE-22"));
        assert!(!is_quarantined_from_default_packs("PERF-101"));
    }

    #[test]
    fn taint_core_tagged() {
        assert_eq!(maturity_for("CWE-89"), RuleMaturity::TaintCore);
    }

    #[test]
    fn bp_63_only_is_reserved() {
        assert_eq!(maturity_for("BP-63"), RuleMaturity::Reserved);
        assert_ne!(maturity_for("BP-64"), RuleMaturity::Reserved);
        assert_ne!(maturity_for("BP-65"), RuleMaturity::Reserved);
    }
}
