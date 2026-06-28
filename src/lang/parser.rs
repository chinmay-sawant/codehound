//! Shared tree-sitter language initialisation.

use std::sync::OnceLock;

use tree_sitter::Language;

pub type LangResult = Result<Language, String>;
pub type LangCache = OnceLock<LangResult>;

pub fn init_language(
    cache: &'static LangCache,
    lang: Language,
) -> Result<&'static Language, String> {
    cache
        .get_or_init(|| {
            let mut p = tree_sitter::Parser::new();
            p.set_language(&lang)
                .map_err(|e| e.to_string())?;
            Ok(lang)
        })
        .as_ref()
        .map_err(|e| e.clone())
}
