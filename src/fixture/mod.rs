//! `.txt` text fixtures → materialized source files for analysis/tests.

mod format;
mod materialize;

pub use format::{
    parse_fixture, FixtureLanguage, TextFixture, FIXTURE_EXTENSION,
};
pub use materialize::{materialize_fixture, materialize_tree, materialized_root};
