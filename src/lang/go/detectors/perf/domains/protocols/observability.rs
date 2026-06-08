#![allow(dead_code)]
//! PERF-091 through PERF-100 detectors (protocols).
//!
//! Framework-specific performance rules: Fiber / fasthttp, gRPC / protobuf,
//! go-redis, Prometheus, and Cobra.

use super::super::super::facts::GoPerfFacts;
use super::super::super::metadata::*;
use crate::ast::walk_nodes;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

/// Returns true when the source text mentions any of the supplied framework
/// markers. Used to gate detectors behind framework-specific imports.
fn source_matches_any(source: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| source.contains(n))
}

const FIBER_MARKERS: &[&str] = &[
    "*fiber.Ctx",
    "fiber.Ctx",
    "fiber.App",
    "fiber.New(",
    "fiber.Config",
    "fiber.Handler",
];
const GRPC_MARKERS: &[&str] = &[
    "RecvMsg(",
    "SendMsg(",
    "grpc.ClientStream",
    "grpc.ServerStream",
    "google.golang.org/grpc",
];
const REDIS_MARKERS: &[&str] = &[
    "redis.Client",
    "*redis.Client",
    "redis.UniversalClient",
    "github.com/redis/go-redis",
    "github.com/go-redis/redis",
];
const PROM_MARKERS: &[&str] = &[
    "prometheus.NewCounterVec",
    "prometheus.NewCounter(",
    "prometheus.NewGaugeVec",
    "prometheus.NewGauge(",
    "prometheus.NewHistogramVec",
    "prometheus.NewHistogram(",
    "prometheus.NewSummaryVec",
    "github.com/prometheus/client_golang",
];
const COBRA_MARKERS: &[&str] = &[
    "cobra.Command{",
    "&cobra.Command{",
    "github.com/spf13/cobra",
];

const HIGH_CARDINALITY_LABELS: &[&str] = &[
    "user_id",
    "userId",
    "userid",
    "request_id",
    "requestId",
    "requestid",
    "uuid",
    "UUID",
    "trace_id",
    "traceId",
    "span_id",
    "spanId",
    "session_id",
    "sessionId",
    "email",
    "ip",
    "client_ip",
    "clientIp",
    "remote_addr",
    "remoteAddr",
    "user",
    "username",
    "account",
    "account_id",
    "accountId",
    "tenant_id",
    "tenantId",
    "order_id",
    "orderId",
    "path",
];

const REDIS_LOOP_TRIGGERS: &[&str] = &[
    "rdb.Set",
    "rdb.Get",
    "rdb.Del",
    "rdb.Incr",
    "rdb.Decr",
    "rdb.HSet",
    "rdb.HGet",
    "rdb.HDel",
    "rdb.LPush",
    "rdb.RPush",
    "rdb.LPop",
    "rdb.RPop",
    "rdb.SAdd",
    "rdb.SRem",
    "rdb.ZAdd",
    "rdb.ZRem",
    "rdb.Expire",
];

const FLAG_METHODS: &[&str] = &[
    "String",
    "Bool",
    "Int",
    "Int64",
    "Duration",
    "Float64",
    "StringSlice",
    "StringArray",
];

/// Returns true when `body` contains `word` as a standalone Go identifier
/// (preceded and followed by non-identifier characters or string boundaries).
fn body_has_identifier(body: &str, word: &str) -> bool {
    let bytes = body.as_bytes();
    let wlen = word.len();
    if wlen == 0 || bytes.len() < wlen {
        return false;
    }
    let mut idx = 0;
    while idx + wlen <= bytes.len() {
        if &bytes[idx..idx + wlen] == word.as_bytes() {
            let before_ok = idx == 0 || !is_ident_byte(bytes[idx - 1]);
            let after_ok = idx + wlen == bytes.len() || !is_ident_byte(bytes[idx + wlen]);
            if before_ok && after_ok {
                return true;
            }
        }
        idx += 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_flag_call(text: &str) -> bool {
    if !text.contains(".Flags().") && !text.contains(".PersistentFlags().") {
        return false;
    }
    FLAG_METHODS.iter().any(|m| {
        let sfx = format!(".{m}(");
        text.contains(&sfx) || text.ends_with(&format!(".{m}"))
    })
}

/// PERF-91: Fiber handler allocates per-request buffers (c.Request.Body,
/// c.Response.BodyWriter, bytes.NewReader) without using sync.Pool.
pub(crate) fn detect_perf_99(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, PROM_MARKERS) {
        return;
    }
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if !matches!(
            callee,
            "prometheus.NewCounterVec"
                | "prometheus.NewGaugeVec"
                | "prometheus.NewHistogramVec"
                | "prometheus.NewSummaryVec"
        ) {
            continue;
        }
        for arg in &call.arguments {
            let t = arg.as_ref();
            if HIGH_CARDINALITY_LABELS.iter().any(|n| t.contains(n)) {
                let (line, col) = unit.line_col(call.start_byte);
                emit::push_finding(
                    &META_PERF_99,
                    file,
                    line,
                    col,
                    "Prometheus metric registers a high-cardinality label (user ID / UUID / path); time series storage will explode — bound the label space",
                    out,
                );
                return;
            }
        }
    }
}

/// PERF-100: cobra.Command with a heavy RunE (large init, repeated flag
/// registration).
pub(crate) fn detect_perf_100(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, COBRA_MARKERS) {
        return;
    }
    // First pass: count distinct flag-registration call sites.
    let mut flag_count = 0usize;
    let mut first_start: Option<usize> = None;
    walk_nodes(unit.tree.root_node(), &["call_expression"], &mut |node| {
        let text = match node.utf8_text(source.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };
        if !is_flag_call(text) {
            return;
        }
        if first_start.is_none() {
            first_start = Some(node.start_byte());
        }
        flag_count += 1;
    });
    if flag_count < 4 {
        return;
    }
    if let Some(start) = first_start {
        let (line, col) = unit.line_col(start);
        emit::push_finding(
            &META_PERF_100,
            file,
            line,
            col,
            "cobra.Command registers many flags inline; defer heavy init to PersistentPreRunE or a sync.Once to keep CLI startup fast",
            out,
        );
    }
}
