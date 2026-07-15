//! Release-mode benchmark for attaching enclosing function context to findings.

use std::hint::black_box;
use std::time::Duration;

use codehound::ast::FunctionSpan;
use codehound::engine::bench_attach_function_context;
use codehound::rules::{Finding, FindingInputs, LineCol, Severity};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

fn findings_and_spans(count: usize) -> (Vec<Finding>, Vec<FunctionSpan>) {
    let mut findings = Vec::with_capacity(count);
    let mut spans = Vec::with_capacity(count);
    for index in 0..count {
        let start_line = index * 10 + 1;
        spans.push(FunctionSpan {
            start_byte: index * 100,
            end_byte: index * 100 + 90,
            start_line,
            end_line: start_line + 8,
            depth: 0,
        });
        findings.push(Finding::new(FindingInputs::new(
            "PERF-BENCH",
            "benchmark finding",
            "bench.go",
            LineCol::try_new(start_line + 1, 1).expect("valid benchmark location"),
            "benchmark",
            Severity::Info,
            std::borrow::Cow::Borrowed(&[]),
        )));
    }
    (findings, spans)
}

fn bench_span_sweep(c: &mut Criterion) {
    for count in [100, 1_000, 10_000] {
        let (template, spans) = findings_and_spans(count);
        c.bench_function(&format!("span_sweep_{count}"), |b| {
            b.iter_batched(
                || template.clone(),
                |mut findings| {
                    bench_attach_function_context(&mut findings, black_box(&spans));
                    black_box(findings);
                },
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().measurement_time(Duration::from_secs(5));
    targets = bench_span_sweep,
}
criterion_main!(benches);
