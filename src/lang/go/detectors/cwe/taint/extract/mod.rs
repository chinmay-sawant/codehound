//! Single-pass tree-sitter extraction of taint-relevant facts.

mod assignments;
mod classify;
mod walker_core;
mod walker_records;

#[cfg(test)]
mod tests;

pub use walker_core::extract_taint_facts;
