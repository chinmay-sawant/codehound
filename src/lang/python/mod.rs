//! Python language plugin (stub + first detector).

mod detectors;
mod loop_kinds;
mod matchers;
mod parser;

use std::path::Path;
use std::sync::Arc;

use crate::Error;
use crate::core::{Detector, LanguageId, LanguagePlugin, ParsedUnit};

pub struct PythonPlugin;

impl LanguagePlugin for PythonPlugin {
    fn id(&self) -> LanguageId {
        LanguageId::Python
    }

    fn extensions(&self) -> &'static [&'static str] {
        &["py"]
    }

    fn configure_parser(&self, parser: &mut tree_sitter::Parser) -> Result<(), Error> {
        parser::configure(parser)
    }

    fn parse_with(
        &self,
        parser: &mut tree_sitter::Parser,
        path: &Path,
        source: Arc<str>,
    ) -> Result<ParsedUnit, Error> {
        parser::parse_with(parser, path, source)
    }

    fn detectors(&self) -> Vec<Box<dyn Detector>> {
        detectors::all()
    }

    fn loop_node_kinds(&self) -> &'static [&'static str] {
        loop_kinds::LOOP_NODE_KINDS
    }
}
