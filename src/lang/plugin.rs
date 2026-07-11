//! Macro to generate marker type + [`LanguagePlugin`] impl in one shot.
//!
//! [`tree_sitter_lang!`] generates a zero-sized marker type implementing
//! [`TreeSitterLang`](crate::lang::parser::TreeSitterLang) and the full
//! [`LanguagePlugin`](crate::core::LanguagePlugin) impl — the simplest
//! entry point for a new language.

/// Combined macro: generates a zero-sized marker type implementing
/// [`TreeSitterLang`](crate::lang::parser::TreeSitterLang) AND the
/// [`LanguagePlugin`](crate::core::LanguagePlugin) impl in one call.
///
/// Optional 10th argument: `extract_deps` closure
/// `|unit, project_root, module_prefix| -> Vec<String>`.
macro_rules! tree_sitter_lang {
    ($marker:ident, $plugin:ident, $lang_id:expr, $grammar:expr, $error_tag:expr,
     $extensions:expr, $detectors:expr, $fn_kinds:expr, $loop_kinds:expr) => {
        $crate::lang::plugin::tree_sitter_lang!(
            $marker,
            $plugin,
            $lang_id,
            $grammar,
            $error_tag,
            $extensions,
            $detectors,
            $fn_kinds,
            $loop_kinds,
            |_, _, _| Vec::new()
        );
    };
    ($marker:ident, $plugin:ident, $lang_id:expr, $grammar:expr, $error_tag:expr,
     $extensions:expr, $detectors:expr, $fn_kinds:expr, $loop_kinds:expr,
     $extract_deps:expr) => {
        pub struct $marker;
        impl crate::lang::parser::TreeSitterLang for $marker {
            const ID: crate::core::LanguageId = $lang_id;
            const ERROR_TAG: &'static str = $error_tag;
            fn language() -> tree_sitter::Language {
                $grammar
            }
        }
        pub struct $plugin;
        impl crate::core::LanguagePlugin for $plugin {
            fn id(&self) -> crate::core::LanguageId {
                $lang_id
            }
            fn extensions(&self) -> &'static [&'static str] {
                $extensions
            }
            fn configure_parser(
                &self,
                parser: &mut tree_sitter::Parser,
            ) -> Result<(), crate::Error> {
                crate::lang::parser::configure::<$marker>(parser)
            }
            fn parse_with(
                &self,
                parser: &mut tree_sitter::Parser,
                path: &std::path::Path,
                source: std::sync::Arc<str>,
            ) -> Result<crate::core::ParsedUnit, crate::Error> {
                crate::lang::parser::parse_with::<$marker>(parser, path, source)
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
            fn extract_deps(
                &self,
                unit: &crate::core::ParsedUnit,
                project_root: &std::path::Path,
                module_prefix: Option<&str>,
            ) -> Vec<String> {
                $extract_deps(unit, project_root, module_prefix)
            }
        }
    };
}

pub(crate) use tree_sitter_lang;
