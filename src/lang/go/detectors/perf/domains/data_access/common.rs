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

pub(crate) fn has_any(source: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| source.contains(n))
}
