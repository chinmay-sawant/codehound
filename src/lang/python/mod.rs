//! Python language plugin (stub + first detector).

mod detectors;
mod parser;

const LOOP_NODE_KINDS: &[&str] = &["for_statement", "while_statement"];

use crate::core::LanguageId;
use crate::lang::plugin::lang_plugin;

pub struct PythonPlugin;

lang_plugin!(
    PythonPlugin,
    LanguageId::Python,
    &["py"],
    detectors::all(),
    &[],
    LOOP_NODE_KINDS
);
