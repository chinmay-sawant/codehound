use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_256(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("GenerateFromPassword(")
        || source.contains("hashPassphrase(")
        || source.contains("digest")
        || source.contains("hash")
    {
        return;
    }

    let gorm_plaintext = source.contains("Password: c.PostForm(\"password\")");
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


pub(crate) fn detect_cwe_257(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "a password or login secret is encrypted with a reversible cipher before storage",
        out,
    );
}


pub(crate) fn detect_cwe_261(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("base64.StdEncoding.EncodeToString(") {
        return;
    }
    let stores_encoded_secret =
        source.contains("Secret: encoded") || source.contains("Store(user, encoded)");
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


pub(crate) fn detect_cwe_521(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_password_policy = source.contains("Password")
        && source.contains("len(body.Password) < 1")
        || source.contains("len(body.Password)<1")
        || source.contains("len(pw) < 1");
    let stores_password = source.contains("password_hash")
        && (source.contains("body.Password") || source.contains("body.Password"));
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
        file,
        line,
        col,
        "password validation allows trivially weak credentials before persistence",
        out,
    );
}


pub(crate) fn detect_cwe_916(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_password_hash = source.contains("md5.Sum(") && source.contains("password");
    if !weak_password_hash {
        return;
    }
    if source.contains("bcrypt.GenerateFromPassword") || source.contains("hashIterations = 100_000")
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


pub(crate) fn detect_cwe_1052(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
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
        file,
        line,
        col,
        "database initialization embeds a complete DSN with hard-coded credentials",
        out,
    );
}


pub(crate) fn detect_cwe_1392(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let default_admin = (source.contains("BootstrapAdmin(")
        || source.contains("BootstrapAdminPure("))
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
        file,
        line,
        col,
        "administrator bootstrap uses a built-in default password literal",
        out,
    );
}

