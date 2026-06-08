//! General-security CWE detectors grouped by thematic cluster.

mod auth_and_identity;
mod crypto_and_integrity;
mod exposure_and_lifecycle;
mod input_and_parsing;
mod path_and_file;
mod permissions_and_ownership;

pub(crate) use auth_and_identity::*;
pub(crate) use crypto_and_integrity::*;
pub(crate) use exposure_and_lifecycle::*;
pub(crate) use input_and_parsing::*;
pub(crate) use path_and_file::*;
pub(crate) use permissions_and_ownership::*;
