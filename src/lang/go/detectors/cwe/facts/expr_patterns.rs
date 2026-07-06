//! User-input and trusted-config expression classifiers.

pub use crate::lang::assignment::{extract_identifiers, split_assignment};

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
