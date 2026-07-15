//! `.txt` text fixtures → materialized source files for analysis/tests.

mod format;
mod materialize;

pub use format::{FIXTURE_EXTENSION, FixtureError, FixtureLanguage, TextFixture, parse_fixture};
pub use materialize::{materialize_fixture, materialize_tree, materialized_root};
