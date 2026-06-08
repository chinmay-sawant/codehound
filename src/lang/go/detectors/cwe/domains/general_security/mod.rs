//! General-security CWE detectors grouped by thematic cluster.

mod authorization_bypass;
mod crypto_and_integrity;
mod environment_exposure;
mod identity_and_authentication;
mod input_and_parsing;
mod lifecycle_and_integrity;
mod path_and_file;
mod permissions_and_ownership;
mod privilege_escalation;

pub(crate) use authorization_bypass::*;
pub(crate) use crypto_and_integrity::*;
pub(crate) use environment_exposure::*;
pub(crate) use identity_and_authentication::*;
pub(crate) use input_and_parsing::*;
pub(crate) use lifecycle_and_integrity::*;
pub(crate) use path_and_file::*;
pub(crate) use permissions_and_ownership::*;
pub(crate) use privilege_escalation::*;
