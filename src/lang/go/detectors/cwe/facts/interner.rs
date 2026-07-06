//! `SharedTextInterner` + record/extract helpers for facts.

use std::collections::HashMap;

use super::types::{AssignmentFact, CallFact, GoUnitFacts, InputBinding, InputKind, SharedText};

#[derive(Default)]
pub(crate) struct SharedTextInterner<'a> {
    pub(crate) values: HashMap<&'a str, SharedText>,
}

impl<'a> SharedTextInterner<'a> {
    pub(crate) fn intern(&mut self, text: &'a str) -> SharedText {
        if let Some(existing) = self.values.get(text) {
            return Arc::clone(existing);
        }

        let shared: SharedText = Arc::from(text);
        self.values.insert(text, Arc::clone(&shared));
        shared
    }
}

pub(crate) fn extract_argument_texts<'a>(
    args_node: tree_sitter::Node,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) -> Box<[SharedText]> {
    let mut out = Vec::new();
    let mut cursor = args_node.walk();
    for child in args_node.named_children(&mut cursor) {
        if let Ok(text) = child.utf8_text(src) {
            out.push(interner.intern(text.trim()));
        }
    }
    out.into_boxed_slice()
}

pub(crate) fn record_call_fact<'a>(
    node: tree_sitter::Node,
    facts: &mut GoUnitFacts,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) {
    let Some(func) = node.child_by_field_name("function") else {
        return;
    };
    let Ok(callee) = func.utf8_text(src) else {
        return;
    };

    let arguments = node
        .child_by_field_name("arguments")
        .map(|args| extract_argument_texts(args, src, interner))
        .unwrap_or_default();

    facts.call_facts.push(CallFact {
        callee: interner.intern(callee),
        arguments,
        start_byte: node.start_byte(),
    });
}

pub(crate) fn record_assignment_fact<'a>(
    node: tree_sitter::Node,
    facts: &mut GoUnitFacts,
    src: &'a [u8],
    interner: &mut SharedTextInterner<'a>,
) {
    let Ok(text) = node.utf8_text(src) else {
        return;
    };
    let Some((lhs, rhs)) = crate::lang::assignment::split_assignment(text) else {
        return;
    };
    let names = crate::lang::assignment::extract_identifiers(lhs);
    if names.is_empty() {
        return;
    }
    let kind = if super::input_classify::is_user_input_expr(rhs) {
        Some(InputKind::UserControlled)
    } else if super::input_classify::is_trusted_config_expr(rhs) {
        Some(InputKind::TrustedConfig)
    } else {
        None
    };
    if let Some(kind) = kind {
        for name in &names {
            facts.input_bindings.push(InputBinding {
                name: interner.intern(name),
                kind,
            });
        }
    }

    for name in names {
        facts.assignments.push(AssignmentFact {
            name: interner.intern(name),
            expr: interner.intern(rhs),
            start_byte: node.start_byte(),
        });
    }
}

// We re-use the `SharedText` type alias and the `Arc` import for the interner.
use std::sync::Arc;
