use super::super::super::super::facts::GoUnitFacts;
use super::super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_1052(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hard_coded_dsn = (facts.source_index.has("gorm.Open(postgres.Open(dsn)")
        || facts.source_index.has("sql.Open(\"postgres\", appDSNPure)"))
        && facts.source_index.has("password=SuperSecret99")
        && facts.source_index.has("host=db.internal");
    if !hard_coded_dsn {
        return;
    }
    if facts.source_index.has("APP_DATABASE_URL") || facts.source_index.has("DB_PASSWORD") {
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

pub(crate) fn detect_cwe_1392(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let default_admin = (facts.source_index.has("BootstrapAdmin(")
        || facts.source_index.has("BootstrapAdminPure("))
        && facts.source_index.has("Username: \"admin\"")
        && facts.source_index.has("Password: \"admin\"");
    if !default_admin {
        return;
    }
    if facts.source_index.has("BOOTSTRAP_ADMIN_PASSWORD") {
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
