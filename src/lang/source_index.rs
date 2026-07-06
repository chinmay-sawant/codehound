//! Shared single-pass substring index for detector hot paths.

/// Precomputed presence of a static needle table for one source file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SourceIndex {
    needles: &'static [&'static str],
    flags: Vec<bool>,
}

impl SourceIndex {
    pub fn build(needles: &'static [&'static str], source: &str) -> Self {
        let flags = needles
            .iter()
            .map(|needle| source.contains(needle))
            .collect();
        Self { needles, flags }
    }

    #[inline]
    pub fn has(&self, needle: &str) -> bool {
        let Some(idx) = self.needles.iter().position(|n| *n == needle) else {
            return false;
        };
        self.flags.get(idx).copied().unwrap_or(false)
    }

    #[inline]
    pub fn has_any(&self, needles: &[&str]) -> bool {
        needles.iter().any(|n| self.has(n))
    }
}