use super::cwe::facts::{
    GoUnitFacts, SharedTextInterner as CweInterner, record_assignment_fact as record_cwe_assign,
    record_call_fact as record_cwe_call,
};
use super::perf::facts::{
    GoPerfFacts, SharedTextInterner as PerfInterner, record_assignment_fact as record_perf_assign,
    record_call_fact as record_perf_call, record_perf_node,
};
use crate::ast;
use crate::ast::FunctionSpan;
use tree_sitter::Node;

pub struct GoFacts {
    pub cwe: GoUnitFacts,
    pub perf: GoPerfFacts,
    pub function_spans: Vec<FunctionSpan>,
}

pub fn build_go_facts(root: Node, source: &str, function_kinds: &[&str]) -> GoFacts {
    let src = source.as_bytes();
    let mut cwe = GoUnitFacts::default();
    let mut perf = GoPerfFacts::default();
    let mut function_spans = Vec::new();
    let mut cwe_interner = CweInterner::default();
    let mut perf_interner = PerfInterner::default();

    ast::walk_calls_and_assignments(root, &mut |node| {
        match node.kind() {
            "call_expression" | "call" => {
                record_cwe_call(node, &mut cwe, src, &mut cwe_interner);
                record_perf_call(node, &mut perf, src, &mut perf_interner);
            }
            "assignment_statement" | "short_var_declaration" => {
                record_cwe_assign(node, &mut cwe, src, &mut cwe_interner);
                record_perf_assign(node, &mut perf, src, &mut perf_interner);
            }
            "defer_statement" | "go_statement" | "for_statement" | "type_assertion_expression" => {
                record_perf_node(node, &mut perf);
            }
            _ => {}
        }
        let _ = crate::ast::try_record_function_span(node, function_kinds, 0, &mut function_spans);
    });

    // PERF: var_spec walk for type classification
    ast::walk_nodes(root, &["var_spec"], &mut |spec| {
        super::perf::facts::collect_var_spec_kinds(
            spec,
            src,
            &mut perf.var_kinds,
            &mut perf_interner,
        );
        let _ = crate::ast::try_record_function_span(spec, function_kinds, 0, &mut function_spans);
    });

    // Resolve line numbers for function spans
    let line_starts = crate::ast::compute_line_starts(source);
    for span in &mut function_spans {
        let (sl, _) = crate::ast::line_col_with_starts(&line_starts, span.start_byte);
        let (el, _) = crate::ast::line_col_with_starts(&line_starts, span.end_byte);
        span.start_line = sl;
        span.end_line = el;
    }

    GoFacts {
        cwe,
        perf,
        function_spans,
    }
}
