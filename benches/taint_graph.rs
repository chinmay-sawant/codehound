//! Release-mode taint graph query signal for adjacency and path reconstruction.

use std::hint::black_box;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use codehound::ast::compute_line_starts;
use codehound::core::{LanguageId, ParsedUnit};
use codehound::lang::go::detectors::cwe::facts::{FactBuildOpts, build_go_unit_facts_with};
use codehound::lang::go::detectors::cwe::taint::{
    EdgeKind, SinkKind, SourceKind, TaintGraph, TaintNode, compute_all_summaries,
    refine_summaries_multihop,
};
use criterion::{Criterion, criterion_group, criterion_main};

fn linear_graph(node_count: usize) -> TaintGraph {
    let mut graph = TaintGraph::default();
    let source = graph.add_node(TaintNode::Source {
        function: "bench".into(),
        kind: SourceKind::UserInput,
        byte_range: 0..1,
    });
    let mut previous = source;
    for index in 1..node_count.saturating_sub(1) {
        let node = graph.add_node(TaintNode::Variable {
            name: format!("value_{index}").into(),
            type_hint: None,
            scope: 0,
            decl_byte: index,
        });
        graph.add_edge(previous, node, EdgeKind::PassThrough);
        previous = node;
    }
    let sink = graph.add_node(TaintNode::Sink {
        function: "bench".into(),
        kind: SinkKind::CommandExec,
        argument_index: 0,
        byte_range: node_count..node_count + 1,
    });
    graph.add_edge(previous, sink, EdgeKind::Argument(0));
    graph
}

fn bench_linear_queries(c: &mut Criterion) {
    for node_count in [1_000, 10_000] {
        let graph = linear_graph(node_count);
        c.bench_function(&format!("taint_linear_query_{node_count}"), |b| {
            b.iter(|| {
                black_box(
                    codehound::lang::go::detectors::cwe::taint::find_taint_paths(
                        black_box(&graph),
                        SourceKind::UserInput,
                        SinkKind::CommandExec,
                        &[],
                    ),
                )
            });
        });
    }
}

fn interprocedural_unit() -> ParsedUnit {
    let source: Arc<str> = Arc::from(
        r#"package sample

import "os"

func caller() {
	value := layer0()
	os.Open(value)
}

func layer0() string { return layer1() }
func layer1() string { return layer2() }
func layer2() string { return layer3() }
func layer3() string { return layer4() }
func layer4() string { return layer5() }
func layer5() string { return os.Getenv("INPUT") }
"#,
    );
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_go::LANGUAGE.into())
        .expect("load Go grammar");
    let tree = parser
        .parse(source.as_ref(), None)
        .expect("parse benchmark source");
    ParsedUnit {
        language: LanguageId::Go,
        path: PathBuf::from("IP-006-vulnerable.go"),
        display_path: String::from("IP-006-vulnerable.go"),
        line_starts: compute_line_starts(source.as_ref()),
        function_spans: Vec::new(),
        source,
        tree,
    }
}

fn bench_interprocedural_summaries(c: &mut Criterion) {
    let unit = interprocedural_unit();
    let facts = build_go_unit_facts_with(&unit, FactBuildOpts::TAINT);
    let call_graph = facts.call_graph.as_ref().expect("call graph extracted");

    c.bench_function("taint_interprocedural_summary_ip006", |b| {
        b.iter(|| {
            let mut summaries = compute_all_summaries(&facts.taint, unit.source.as_ref());
            refine_summaries_multihop(call_graph, &mut summaries, 4);
            black_box(summaries);
        });
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = bench_linear_queries, bench_interprocedural_summaries,
}
criterion_main!(benches);
