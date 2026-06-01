//! Reused tree-sitter parsers (one per language per scan).

use std::collections::HashMap;

use tree_sitter::Parser;

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

    pub fn parser_for(&mut self, plugin: &dyn LanguagePlugin) -> &mut Parser {
        let id = plugin.id();
        if !self.parsers.contains_key(&id) {
            let mut parser = Parser::new();
            plugin.configure_parser(&mut parser);
            self.parsers.insert(id, parser);
        }
        self.parsers.get_mut(&id).expect("parser just inserted")
    }
}
