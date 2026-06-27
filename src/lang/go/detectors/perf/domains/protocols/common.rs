use super::super::super::source_index::PerfSourceIndex;

pub(crate) fn index_matches_any(index: &PerfSourceIndex, needles: &[&str]) -> bool {
    index.has_any(needles)
}

pub(crate) const FIBER_MARKERS: &[&str] = &[
    "*fiber.Ctx",
    "fiber.Ctx",
    "fiber.App",
    "fiber.New(",
    "fiber.Config",
    "fiber.Handler",
];
pub(crate) const GRPC_MARKERS: &[&str] = &[
    "RecvMsg(",
    "SendMsg(",
    "grpc.ClientStream",
    "grpc.ServerStream",
    "google.golang.org/grpc",
];
pub(crate) const REDIS_MARKERS: &[&str] = &[
    "redis.Client",
    "*redis.Client",
    "redis.UniversalClient",
    "github.com/redis/go-redis",
    "github.com/go-redis/redis",
];
pub(crate) const PROM_MARKERS: &[&str] = &[
    "prometheus.NewCounterVec",
    "prometheus.NewCounter(",
    "prometheus.NewGaugeVec",
    "prometheus.NewGauge(",
    "prometheus.NewHistogramVec",
    "prometheus.NewHistogram(",
    "prometheus.NewSummaryVec",
    "github.com/prometheus/client_golang",
];
pub(crate) const COBRA_MARKERS: &[&str] = &[
    "cobra.Command{",
    "&cobra.Command{",
    "github.com/spf13/cobra",
];

pub(crate) const HIGH_CARDINALITY_LABELS: &[&str] = &[
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

pub(crate) const REDIS_LOOP_TRIGGERS: &[&str] = &[
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

pub(crate) const FLAG_METHOD_SFX: &[&str] = &[
    ".String(",
    ".Bool(",
    ".Int(",
    ".Int64(",
    ".Duration(",
    ".Float64(",
    ".StringSlice(",
    ".StringArray(",
];

pub(crate) fn body_has_identifier(body: &str, word: &str) -> bool {
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

pub(crate) fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub(crate) fn is_flag_call(text: &str) -> bool {
    if !text.contains(".Flags().") && !text.contains(".PersistentFlags().") {
        return false;
    }
    FLAG_METHOD_SFX.iter().any(|sfx| text.contains(sfx))
}
