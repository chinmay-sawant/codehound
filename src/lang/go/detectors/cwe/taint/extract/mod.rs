//! Single-pass tree-sitter extraction of taint-relevant facts.

mod call_graph;
mod classify;
mod imports;
mod walker_core;
mod walker_records;

#[cfg(test)]
mod tests;

pub use call_graph::{extract_call_graph, merge_call_graphs};
pub use imports::build_import_map;
pub use walker_core::extract_taint_facts;
