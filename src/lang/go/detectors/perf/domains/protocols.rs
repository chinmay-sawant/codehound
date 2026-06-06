//! PERF-091 through PERF-100 detectors (protocols).
//!
//! Framework-specific performance rules: Fiber / fasthttp, gRPC / protobuf,
//! go-redis, Prometheus, and Cobra.

use super::super::common::is_in_loop;
use super::super::facts::GoPerfFacts;
use super::super::metadata::*;
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
pub(crate) fn detect_perf_91(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, FIBER_MARKERS) {
        return;
    }
    if source.contains("sync.Pool") || source.contains("bytePool") {
        return;
    }
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if matches!(
            callee,
            "c.Request.Body" | "c.Request.BodyStream" | "c.Response.BodyWriter" | "bytes.NewReader"
        ) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_91,
                file,
                line,
                col,
                "Fiber handler allocates a per-request buffer without using a sync.Pool; reuse buffers across requests",
                out,
            );
            return;
        }
    }
}

/// PERF-92: Fiber handler captures c inside a goroutine instead of using
/// c.UserContext().
pub(crate) fn detect_perf_92(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, FIBER_MARKERS) {
        return;
    }
    walk_nodes(unit.tree.root_node(), &["go_statement"], &mut |node| {
        let text = match node.utf8_text(source.as_bytes()) {
            Ok(t) => t,
            Err(_) => return,
        };
        if text.contains("c.UserContext()") || text.contains("c.Context()") {
            return;
        }
        if body_has_identifier(text, "c") {
            let (line, col) = unit.line_col(node.start_byte());
            emit::push_finding(
                &META_PERF_92,
                file,
                line,
                col,
                "Fiber *fiber.Ctx is captured inside a goroutine; the ctx is reused per request and will race — use c.UserContext()",
                out,
            );
        }
    });
}

/// PERF-93: Fiber handler allocates JSON encoder (c.JSON / json.NewEncoder)
/// per request on a hot path.
pub(crate) fn detect_perf_93(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, FIBER_MARKERS) {
        return;
    }
    if source.contains("encoderPool") || source.contains("jsonPool") {
        return;
    }
    if !source.contains("c.JSON(") && !source.contains("json.NewEncoder(") {
        return;
    }
    for call in &facts.calls {
        if matches!(call.callee.as_ref(), "c.JSON" | "json.NewEncoder") {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_93,
                file,
                line,
                col,
                "JSON response is allocated per request in a Fiber handler; reuse a pooled encoder",
                out,
            );
            return;
        }
    }
}

/// PERF-94: Fiber handler uses io.ReadAll on the request body or calls
/// c.Body() where c.PostBody() zero-copy would suffice.
pub(crate) fn detect_perf_94(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, FIBER_MARKERS) {
        return;
    }
    for call in &facts.calls {
        match call.callee.as_ref() {
            "io.ReadAll" => {
                if let Some(arg) = call.arguments.first() {
                    let t = arg.as_ref();
                    if t.contains("RequestBodyStream")
                        || t.contains("BodyStream")
                        || t.contains("c.Request.Body")
                    {
                        let (line, col) = unit.line_col(call.start_byte);
                        emit::push_finding(
                            &META_PERF_94,
                            file,
                            line,
                            col,
                            "io.ReadAll on a Fiber body stream triggers an extra copy; use c.PostBody() for zero-copy reads",
                            out,
                        );
                        return;
                    }
                }
            }
            "c.Body" => {
                let (line, col) = unit.line_col(call.start_byte);
                emit::push_finding(
                    &META_PERF_94,
                    file,
                    line,
                    col,
                    "c.Body() copies the request body; use c.PostBody() for zero-copy access in Fiber handlers",
                    out,
                );
                return;
            }
            _ => {}
        }
    }
}

/// PERF-95: Fiber app registers many app.Use middleware calls in a row.
pub(crate) fn detect_perf_95(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("fiber.New(")
        && !source.contains("fiber.App")
        && !source.contains("app.Use(")
        && !source.contains("app.Group(")
    {
        return;
    }
    let first = facts.calls.iter().find(|c| c.callee.as_ref() == "app.Use");
    let use_count = facts
        .calls
        .iter()
        .filter(|c| c.callee.as_ref() == "app.Use")
        .count();
    if use_count < 2 {
        return;
    }
    if let Some(call) = first {
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_95,
            file,
            line,
            col,
            "Fiber app registers multiple app.Use middlewares; group them by route to keep the per-request chain small",
            out,
        );
    }
}

/// PERF-96: gRPC client stream allocates a new message struct inside the
/// Recv loop on every iteration.
pub(crate) fn detect_perf_96(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, GRPC_MARKERS) || !source.contains("RecvMsg(") {
        return;
    }
    if source.contains("msg.Reset()") || source.contains("m.Reset()") {
        return;
    }
    for call in &facts.calls {
        if call.callee.as_ref() != "stream.RecvMsg" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let Some(loop_start) = call.enclosing_loop else {
            continue;
        };
        let has_alloc_in_loop = facts.assignments.iter().any(|a| {
            a.enclosing_loop == Some(loop_start)
                && (a.expr.contains("New") || (a.expr.contains('&') && a.expr.contains('{')))
        });
        if has_alloc_in_loop {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding(
                &META_PERF_96,
                file,
                line,
                col,
                "gRPC client allocates a new message inside the Recv loop; reuse a single message struct across iterations",
                out,
            );
            return;
        }
    }
}

/// PERF-97: proto.Marshal / protojson.Marshal invoked inside a loop without
/// buffer reuse.
pub(crate) fn detect_perf_97(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source.contains("proto.Marshal") && !source.contains("protojson.Marshal") {
        return;
    }
    if source.contains("bytesPool")
        || source.contains("bufPool")
        || source.contains("MarshalBuffer")
    {
        return;
    }
    if source.contains("MarshalOptions{")
        && (source.contains("Pool") || source.contains("pool.Get"))
    {
        return;
    }
    for call in &facts.calls {
        let callee = call.callee.as_ref();
        if callee != "proto.Marshal" && callee != "protojson.Marshal" {
            continue;
        }
        if !is_in_loop(call) {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_97,
            file,
            line,
            col,
            "proto.Marshal is called inside a loop; reuse a MarshalOptions/buffer pool to avoid repeated allocations",
            out,
        );
        return;
    }
}

/// PERF-98: go-redis sequential client calls in a loop without using
/// Pipeline / Pipelined / TxPipeline.
pub(crate) fn detect_perf_98(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();
    if !source_matches_any(source, REDIS_MARKERS) {
        return;
    }
    if source.contains(".Pipeline()")
        || source.contains(".Pipelined(")
        || source.contains(".TxPipeline()")
        || source.contains(".TxPipelined(")
    {
        return;
    }
    for call in &facts.calls {
        if !is_in_loop(call) {
            continue;
        }
        if !REDIS_LOOP_TRIGGERS
            .iter()
            .any(|t| call.callee.as_ref() == *t)
        {
            continue;
        }
        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_PERF_98,
            file,
            line,
            col,
            "go-redis client is called inside a loop without a pipeline; batch the calls with rdb.Pipeline() to amortise round-trips",
            out,
        );
        return;
    }
}

/// PERF-99: Prometheus metric registered with a high-cardinality label
/// (user_id, request_id, UUID, email, ip, etc.).
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
