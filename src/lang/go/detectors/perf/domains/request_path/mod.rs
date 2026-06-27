mod crypto_and_keys;
mod reflection_and_io;
mod strings_and_copies;

pub(crate) use crypto_and_keys::*;
pub(crate) use reflection_and_io::*;
pub(crate) use strings_and_copies::*;

use super::super::common::{has_echo_handler, has_gin_handler, has_http_handler, is_request_path};
use super::super::source_index::PerfSourceIndex;

pub(super) fn is_request_handler(index: &PerfSourceIndex) -> bool {
    is_request_path(index)
        && (index.has("gin.HandlerFunc")
            || index.has("echo.HandlerFunc")
            || index.has("http.HandlerFunc")
            || index.has("func Handle")
            || index.has("func ServeHTTP")
            || index.has("c.JSON(")
            || index.has("c.String(")
            || index.has("c.HTML(")
            || index.has("c.Bind(")
            || index.has("c.ShouldBind")
            || has_gin_handler(index)
            || has_echo_handler(index)
            || has_http_handler(index))
}