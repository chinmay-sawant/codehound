//! Macro to generate boilerplate [`LanguagePlugin`] impls.
//!
//! Every plugin impl follows the same shape — only the identity, extensions,
//! detector registry, and node-kind lists differ.

macro_rules! lang_plugin {
    ($ty:ident, $id:expr, $ext:expr, $detectors:expr, $fn_kinds:expr, $loop_kinds:expr) => {
        impl crate::core::LanguagePlugin for $ty {
            fn id(&self) -> crate::core::LanguageId {
                $id
            }

            fn extensions(&self) -> &'static [&'static str] {
                $ext
            }

            fn configure_parser(
                &self,
                parser: &mut tree_sitter::Parser,
            ) -> Result<(), crate::Error> {
                parser::configure(parser)
            }

            fn parse_with(
                &self,
                parser: &mut tree_sitter::Parser,
                path: &std::path::Path,
                source: std::sync::Arc<str>,
            ) -> Result<crate::core::ParsedUnit, crate::Error> {
                parser::parse_with(parser, path, source)
            }

            fn detectors(&self) -> Vec<Box<dyn crate::core::Detector>> {
                $detectors
            }

            fn function_node_kinds(&self) -> &'static [&'static str] {
                $fn_kinds
            }

            fn loop_node_kinds(&self) -> &'static [&'static str] {
                $loop_kinds
            }
        }
    };
}

pub(crate) use lang_plugin;
