//! Application orchestration and subcommands.

mod baseline_cmd;
mod cache;
mod config;
mod exit_codes;
mod init_cmd;
mod rule_info;
mod run;

pub use exit_codes::{EXIT_CONFIG, exit_code_for_error};
pub use run::run;
