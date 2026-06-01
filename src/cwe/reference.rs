//! CWE reference type.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CweRef {
    pub id: u32,
    pub name: &'static str,
    pub url: &'static str,
}

impl CweRef {
    pub const fn new(id: u32, name: &'static str, url: &'static str) -> Self {
        Self { id, name, url }
    }
}
