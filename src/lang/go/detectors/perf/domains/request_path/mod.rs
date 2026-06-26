mod crypto_and_keys;
mod reflection_and_io;
mod strings_and_copies;

pub(crate) use crypto_and_keys::*;
pub(crate) use reflection_and_io::*;
pub(crate) use strings_and_copies::*;

use super::super::common::{
    has_echo_handler, has_gin_handler, has_http_handler, is_request_path,
};

pub(super) fn is_request_handler(source: &str) -> bool {
    is_request_path(source)
        && (source.contains("gin.HandlerFunc")
            || source.contains("echo.HandlerFunc")
            || source.contains("http.HandlerFunc")
            || source.contains("func Handle")
            || source.contains("func ServeHTTP")
            || source.contains("c.JSON(")
            || source.contains("c.String(")
            || source.contains("c.HTML(")
            || source.contains("c.Bind(")
            || source.contains("c.ShouldBind")
            || has_gin_handler(source)
            || has_echo_handler(source)
            || has_http_handler(source))
}
