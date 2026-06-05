//! Go language plugin.

pub mod detectors;
mod loop_kinds;
mod matchers;
mod parser;
mod scan;

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use crate::core::{Detector, LanguageId, LanguagePlugin, ParsedUnit};

pub use loop_kinds::LOOP_NODE_KINDS;

pub struct GoPlugin;

impl LanguagePlugin for GoPlugin {
    fn id(&self) -> LanguageId {
        LanguageId::Go
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["go"]
    }

    fn configure_parser(&self, parser: &mut tree_sitter::Parser) {
        parser::configure(parser);
    }

    fn parse_with(
        &self,
        parser: &mut tree_sitter::Parser,
        path: &Path,
        source: Arc<str>,
    ) -> Result<ParsedUnit> {
        parser::parse_with(parser, path, source)
    }

    fn detectors(&self) -> Vec<Box<dyn Detector>> {
        detectors::all()
    }

    fn loop_node_kinds(&self) -> &'static [&'static str] {
        LOOP_NODE_KINDS
    }
}
