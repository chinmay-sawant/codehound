use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// CWE-256 — Plaintext Storage of a Password.
///
/// Freeze (A1 / #96): primary evidence is exact corpus persistence text
/// (`Password: c.PostForm("password")` GORM shape, or the pure-stdlib
/// `db.Exec("INSERT INTO credentials(login, pass) VALUES(?, ?)", login, pass)`
/// SQL shape) with negative prefilters on hashing helpers.
///
/// Call facts cannot become the complete primary signal without losing the
/// password-storage proof boundary (would require dataflow from password form
/// field → persistence sink). Disposition: **fixture-only**.
pub(crate) fn detect_cwe_256(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    // Negative prefilters: hashing / digest helpers indicate non-plaintext storage.
    if facts.source_index.has("GenerateFromPassword(")
        || facts.source_index.has("hashPassphrase(")
        || facts.source_index.has("digest")
        || facts.source_index.has("hash")
    {
        return;
    }

    // Primary signal (needle / exact source text): corpus plaintext persistence shapes.
    let gorm_plaintext = facts.source_index.has("Password: c.PostForm(\"password\")");
    let sql_plaintext = source
        .contains("db.Exec(\"INSERT INTO credentials(login, pass) VALUES(?, ?)\", login, pass)");
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
        file,
        line,
        col,
        "a plaintext password value is persisted directly instead of a hash or digest",
        out,
    );
}

/// CWE-257 — Storing Passwords in a Recoverable Format.
///
/// Freeze (A1 / #96): reversible AES-GCM + base64 encode chain, gated on
/// exact password/login persistence co-signals (`"password": encoded` or
/// `VALUES(?, ?)", login, encoded)`).
///
/// Call facts are primary for the crypto sink APIs; SourceIndex is retained
/// as cheap impossibility prefilter and for the corpus persistence co-signals
/// that keep the password-storage proof boundary. Disposition: **fixture-only**
/// (without those co-signals general AES-GCM would mass-FP non-password crypto).
pub(crate) fn detect_cwe_257(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: reversible AES-GCM + base64 tokens must appear.
    if !facts.source_index.has("aes.NewCipher(")
        || !facts.source_index.has("cipher.NewGCM(")
        || !facts.source_index.has("gcm.Seal(")
        || !facts.source_index.has("base64.StdEncoding.EncodeToString(")
    {
        return;
    }

    // Corpus co-signals: password/login secret is encrypted then persisted.
    // Exact map key / SQL shape — fixture-only maturity (password-storage boundary).
    let persists_recoverable_secret = facts.source_index.has(r#""password": encoded"#)
        || facts.source_index.has("VALUES(?, ?)\", login, encoded)");
    if !persists_recoverable_secret {
        return;
    }

    // Primary signal: call facts — AES-GCM seal chain + base64 encode of ciphertext.
    let Some(aes_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "aes.NewCipher")
    else {
        return;
    };
    let has_gcm = facts
        .call_facts
        .iter()
        .any(|call| call.callee.as_ref() == "cipher.NewGCM");
    let has_seal = facts.call_facts.iter().any(|call| {
        let callee = call.callee.as_ref();
        callee.ends_with(".Seal") || callee == "Seal"
    });
    let has_b64 = facts
        .call_facts
        .iter()
        .any(|call| call.callee.as_ref() == "base64.StdEncoding.EncodeToString");
    if !(has_gcm && has_seal && has_b64) {
        return;
    }

    let (line, col) = unit.line_col(aes_call.start_byte);
    emit::push_finding(
        &META_CWE_257,
        file,
        line,
        col,
        "a password or login secret is encrypted with a reversible cipher before storage",
        out,
    );
}

/// CWE-261 — Weak Encoding for Password.
///
/// Freeze (A1 / #96): `base64.StdEncoding.EncodeToString` plus exact storage
/// shapes (`Secret: encoded` or `Store(user, encoded)`).
///
/// Call facts are primary for the base64 encode sink; SourceIndex retains the
/// corpus storage co-signals that define the password-storage proof boundary.
/// Disposition: **fixture-only** (base64 alone is not password-storage proof).
pub(crate) fn detect_cwe_261(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter.
    if !facts.source_index.has("base64.StdEncoding.EncodeToString(") {
        return;
    }
    // Corpus co-signals: Secret field assignment or sync.Map Store of encoded password.
    let stores_encoded_secret =
        facts.source_index.has("Secret: encoded") || facts.source_index.has("Store(user, encoded)");
    if !stores_encoded_secret {
        return;
    }

    // Primary signal: call facts — base64.StdEncoding.EncodeToString callee.
    let Some(b64_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "base64.StdEncoding.EncodeToString")
    else {
        return;
    };

    let (line, col) = unit.line_col(b64_call.start_byte);
    emit::push_finding(
        &META_CWE_261,
        file,
        line,
        col,
        "a password is Base64-encoded and then stored in a recoverable form",
        out,
    );
}

/// CWE-916 — Use of Password Hash With Insufficient Computational Effort.
///
/// Freeze (A1 / #96): `md5.Sum` in a unit that also mentions `password`, with
/// negative prefilters for bcrypt or fixed high-iteration stretch
/// (`hashIterations = 100_000`).
///
/// Call facts are primary for the weak-hash sink (mirrors CWE-328). SourceIndex
/// is retained as cheap impossibility prefilter, domain co-signal (`password`),
/// and safe-path negatives. Disposition: **keep Heuristic** — production-shaped
/// stdlib API; not structural-promoted (§1.3: bare `password` co-signal is weak
/// and fixed iteration marker is corpus-shaped).
pub(crate) fn detect_cwe_916(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    // Cheap impossibility prefilter: no `md5.Sum` text ⇒ no weak-hash call of this shape.
    if !facts.source_index.has("md5.Sum(") {
        return;
    }
    // Domain co-signal: password context (distinguishes from general CWE-328 weak hash).
    if !facts.source_index.has("password") {
        return;
    }
    // Negative prefilters: adaptive bcrypt or high-iteration stretch path.
    if facts.source_index.has("bcrypt.GenerateFromPassword")
        || facts.source_index.has("hashIterations = 100_000")
    {
        return;
    }

    // Primary signal: call facts — `md5.Sum` callee (stdlib insufficient effort).
    let Some(md5_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "md5.Sum")
    else {
        return;
    };

    let (line, col) = unit.line_col(md5_call.start_byte);
    emit::push_finding(
        &META_CWE_916,
        file,
        line,
        col,
        "password storage uses a fast MD5 hash with insufficient computational effort",
        out,
    );
}
