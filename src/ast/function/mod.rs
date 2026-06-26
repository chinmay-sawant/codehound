//! Function-context detection.
//!
//! The set of kinds that should be considered "function-like" is supplied
//! by the language plugin via [`crate::core::LanguagePlugin::function_node_kinds`].

mod collect;
mod span;

pub(crate) use collect::try_record_function_span;
pub use collect::{FunctionSpan, collect_function_spans};
pub use span::enclosing_function;
