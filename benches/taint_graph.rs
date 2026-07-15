//! Release-mode taint graph query signal for adjacency and path reconstruction.

use std::hint::black_box;
use std::time::Duration;

use codehound::lang::go::detectors::cwe::taint::{
    EdgeKind, SinkKind, SourceKind, TaintGraph, TaintNode,
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

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = bench_linear_queries,
}
criterion_main!(benches);
