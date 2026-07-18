//! PERF rule tiers for product packs and severity policy.
//!
//! | Tier | Meaning | CI default |
//! |------|---------|------------|
//! | **S** | Ship — proven request-path footguns | `recommended` |
//! | **A** | Framework / hot-path | `perf` profile |
//! | **B** | Micro-opt | `all` only, severity info |
//! | **C** | Overlaps staticcheck/gocritic/prealloc | documented, low priority |

/// S-tier: ship in the recommended CI pack.
pub const TIER_S: &[u32] = &[
    1,   // regex compile in loop
    7,   // defer in loop
    50,  // regexp.MatchString in loop
    58,  // Gin request body not closed
    71,  // GORM N+1
    101, // http.Server timeouts
    103, // response body not closed
    189, // body not drained before close
    190, // HTTP client missing timeout
];

/// A-tier: framework + hot-path (perf profile).
pub const TIER_A: &[u32] = &[
    11,  // HTTP client reuse
    12,  // SQL prepare reuse
    22,  // file read in handler
    31,  // defer in hot function
    82,  // sqlx row scan
    85,  // sqlx named query reuse
    142, // MaxBytesReader
    143, // TimeoutHandler
    164, // missing context in DB calls
    183, // WithTimeout inside loop
    210, // redis KEYS
    213, // cache without eviction
];

/// B-tier micro-opts: keep in catalog under `all`, severity Info (not CI-failing under recommended).
pub const TIER_B: &[u32] = &[
    15,  // string concat
    17,  // string builder in loop (overlap)
    18,  // unnecessary slice copy
    19,  // range value copy
    35,  // interface boxing
    42,  // fmt.Errorf static string
    46,  // strings.Trim* on hot path (advisory; intentional header trim is common)
    120, // time.Now().Sub vs Since
    122, // HasPrefix+slice vs TrimPrefix
    127, // fmt.Sprintf in log
    145, // r.WithContext in middleware (advisory; stdlib allocates by design)
    146, // fmt.Sprintf single string
    157, // fmt.Sprint single string
    188, // fmt.Sscanf hot path
];

/// C-tier: strongly overlaps staticcheck / gocritic / prealloc — prefer those tools.
/// Still registered under `--profile all` but documented as duplicate.
pub const TIER_C: &[u32] = &[
    2,  // string builder reuse (prealloc-adjacent)
    3,  // slice reuse
    4,  // map reuse
    6,  // fmt buffer
    16, // bytes.Buffer reuse
];

/// Severity policy by PERF numeric id.
pub const fn severity_for_tier(id: u32) -> crate::rules::Severity {
    if contains_u32(TIER_S, id) || contains_u32(TIER_A, id) {
        crate::rules::Severity::Medium
    } else if contains_u32(TIER_B, id) || contains_u32(TIER_C, id) {
        crate::rules::Severity::Info
    } else {
        // Unclassified PERF: keep Medium (historical catalog default) so
        // --profile all exit policy still gates them under MediumAsErrors.
        crate::rules::Severity::Medium
    }
}

const fn contains_u32(list: &[u32], id: u32) -> bool {
    let mut i = 0;
    while i < list.len() {
        if list[i] == id {
            return true;
        }
        i += 1;
    }
    false
}

/// Format PERF ids as `PERF-N` strings for pack allow-lists.
pub fn tier_rule_ids(tier: &[u32]) -> Vec<String> {
    tier.iter().map(|n| format!("PERF-{n}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Severity;

    #[test]
    fn s_tier_is_medium() {
        assert_eq!(severity_for_tier(101), Severity::Medium);
        assert_eq!(severity_for_tier(1), Severity::Medium);
    }

    #[test]
    fn b_tier_is_info() {
        assert_eq!(severity_for_tier(42), Severity::Info);
        assert_eq!(severity_for_tier(46), Severity::Info);
        assert_eq!(severity_for_tier(120), Severity::Info);
        assert_eq!(severity_for_tier(145), Severity::Info);
    }

    #[test]
    fn tiers_disjoint_s_and_b() {
        for id in TIER_S {
            assert!(!contains_u32(TIER_B, *id), "S/B overlap PERF-{id}");
        }
    }
}
