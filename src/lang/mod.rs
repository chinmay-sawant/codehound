//! Language plugins registry.

pub mod assignment;
pub mod source_index;

#[cfg(feature = "go")]
pub mod go;

#[cfg(feature = "python")]
pub mod python;

mod parser;
mod plugin;
mod register;

pub use register::enabled_plugins;
