//! Collect and parse source files from paths.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use ignore::WalkBuilder;

use crate::core::{LanguageId, ParsedUnit};
use crate::engine::parse_pool::ParsePool;
use crate::engine::registry::Registry;

/// Walk paths and parse supported source files.
pub fn collect_units<I, P>(
    registry: &Registry,
    paths: I,
    lang_filter: Option<LanguageId>,
) -> Result<Vec<ParsedUnit>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut units = Vec::new();
    let mut pool = ParsePool::new();

    for path in paths {
        let path = path.as_ref();
        for entry in WalkBuilder::new(path)
            .standard_filters(true)
            .build()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let Some(plugin) = registry.plugin_for_path(entry.path()) else {
                continue;
            };
            if let Some(want) = lang_filter {
                if plugin.id() != want {
                    continue;
                }
            }
            let bytes = std::fs::read(entry.path())?;
            let source = Arc::from(std::str::from_utf8(&bytes)?.to_owned());
            let parser = pool.parser_for(plugin);
            let unit = plugin
                .parse_with(parser, entry.path(), source)
                .with_context(|| format!("parsing {}", entry.path().display()))?;
            units.push(unit);
        }
    }
    Ok(units)
}
