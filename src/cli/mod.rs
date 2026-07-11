//! Command-line argument definitions.

mod args;
mod enums;
mod severity_args;

pub use args::Cli;
pub use enums::{
    BaselineAction, CacheAction, Command, LangMode, OutputFormat, ProfileArg, RuleCategory,
};
pub use severity_args::SeverityArgs;
