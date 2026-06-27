//! Reused tree-sitter parsers (one per language per Rayon worker).

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use tree_sitter::Parser;

use crate::Error;
use crate::core::{LanguageId, LanguagePlugin};

pub struct ParsePool {
    parsers: HashMap<LanguageId, Parser>,
}

impl ParsePool {
    pub fn new() -> Self {
        Self {
            parsers: HashMap::new(),
        }
    }

    pub fn parser_for(&mut self, plugin: &dyn LanguagePlugin) -> Result<&mut Parser, Error> {
        let id = plugin.id();
        match self.parsers.entry(id) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => {
                let mut parser = Parser::new();
                plugin.configure_parser(&mut parser)?;
                Ok(entry.insert(parser))
            }
        }
    }
}
