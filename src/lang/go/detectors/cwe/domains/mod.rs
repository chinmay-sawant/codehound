//! Domain-grouped Go CWE detector implementations.

mod access_control;
mod concurrency;
mod configuration;
mod credentials_and_secrets;
mod cryptography;
mod deserialization;
mod file_handling;
mod general_security;
mod information_exposure;
mod injection;
mod input_validation;
mod input_validation_redos;
mod network_binding;
mod path_traversal;
mod request_handling;

pub(crate) use access_control::*;
pub(crate) use concurrency::*;
pub(crate) use configuration::*;
pub(crate) use credentials_and_secrets::*;
pub(crate) use cryptography::*;
pub(crate) use deserialization::*;
pub(crate) use file_handling::*;
pub(crate) use general_security::*;
pub(crate) use information_exposure::*;
pub(crate) use injection::*;
pub(crate) use input_validation::*;
pub(crate) use input_validation_redos::*;
pub(crate) use network_binding::*;
pub(crate) use path_traversal::*;
pub(crate) use request_handling::*;
