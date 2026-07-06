use super::super::super::facts::GoPerfFacts;

pub(crate) fn call_in_loop_with(facts: &GoPerfFacts, needles: &[&str]) -> Option<usize> {
    facts.calls.iter().find_map(|c| {
        if c.enclosing_loop.is_some() && needles.iter().any(|n| c.callee.contains(n)) {
            Some(c.start_byte)
        } else {
            None
        }
    })
}

/// Substring-level presence check (not backed by the file-level index).
pub(crate) fn substr_has_any(s: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| s.contains(n))
}
