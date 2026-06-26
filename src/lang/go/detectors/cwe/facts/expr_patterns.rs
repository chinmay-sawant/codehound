//! Assignment-pattern helpers: `split_assignment`, `extract_identifiers`,
//! `is_user_input_expr`, `is_trusted_config_expr`.

#[doc(hidden)]
pub fn split_assignment(text: &str) -> Option<(&str, &str)> {
    if let Some((lhs, rhs)) = text.split_once(":=") {
        return Some((lhs.trim(), rhs.trim()));
    }
    let (lhs, rhs) = text.split_once('=')?;
    Some((lhs.trim(), rhs.trim()))
}

#[doc(hidden)]
pub fn extract_identifiers(lhs: &str) -> Vec<&str> {
    lhs.split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .collect()
}

#[doc(hidden)]
pub fn is_user_input_expr(expr: &str) -> bool {
    expr.contains(".Query(")
        || expr.contains(".URL.Query().Get(")
        || expr.contains(".PostForm(")
        || expr.contains(".FormValue(")
        || expr.contains(".Param(")
        || expr.contains(".PathValue(")
        || expr.contains(".GetHeader(")
        || expr.contains(".Header.Get(")
        || expr.contains(".GetRawData(")
        || expr.contains("io.ReadAll(r.Body)")
}

#[doc(hidden)]
pub fn is_trusted_config_expr(expr: &str) -> bool {
    expr.contains("os.Getenv(") || expr.contains("os.LookupEnv(")
}
