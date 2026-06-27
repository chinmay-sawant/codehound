use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_256(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if facts.source_index.has("GenerateFromPassword(")
        || facts.source_index.has("hashPassphrase(")
        || facts.source_index.has("digest")
        || facts.source_index.has("hash")
    {
        return;
    }

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

pub(crate) fn detect_cwe_257(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let uses_reversible_crypto = facts.source_index.has("aes.NewCipher(")
        && facts.source_index.has("cipher.NewGCM(")
        && facts.source_index.has("gcm.Seal(")
        && facts.source_index.has("base64.StdEncoding.EncodeToString(");
    if !uses_reversible_crypto {
        return;
    }

    let persists_recoverable_secret = facts.source_index.has(r#""password": encoded"#)
        || facts.source_index.has("VALUES(?, ?)\", login, encoded)");
    if !persists_recoverable_secret {
        return;
    }

    let start_byte = source.find("aes.NewCipher(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_257,
        file,
        line,
        col,
        "a password or login secret is encrypted with a reversible cipher before storage",
        out,
    );
}

pub(crate) fn detect_cwe_261(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !facts.source_index.has("base64.StdEncoding.EncodeToString(") {
        return;
    }
    let stores_encoded_secret =
        facts.source_index.has("Secret: encoded") || facts.source_index.has("Store(user, encoded)");
    if !stores_encoded_secret {
        return;
    }

    let start_byte = source
        .find("base64.StdEncoding.EncodeToString(")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_261,
        file,
        line,
        col,
        "a password is Base64-encoded and then stored in a recoverable form",
        out,
    );
}

pub(crate) fn detect_cwe_916(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_password_hash = facts.source_index.has("md5.Sum(") && facts.source_index.has("password");
    if !weak_password_hash {
        return;
    }
    if facts.source_index.has("bcrypt.GenerateFromPassword") || facts.source_index.has("hashIterations = 100_000")
    {
        return;
    }

    let start_byte = source.find("md5.Sum(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_916,
        file,
        line,
        col,
        "password storage uses a fast MD5 hash with insufficient computational effort",
        out,
    );
}
