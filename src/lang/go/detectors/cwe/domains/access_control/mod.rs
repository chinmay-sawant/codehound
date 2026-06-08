//! access_control CWE detectors grouped by thematic cluster.

mod auth_and_validation;
mod authorization_and_scoping;
mod file_permissions;

pub(crate) use auth_and_validation::*;
pub(crate) use authorization_and_scoping::*;
pub(crate) use file_permissions::*;
