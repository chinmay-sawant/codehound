//! Go bad-practice heuristics (P2.5 MVP).

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::cwe::CweRef;
use crate::rules::{Finding, Rule, RuleMetadata, Severity};

mod rules;

use rules::*;

type BadPracticeFn = fn(&ParsedUnit, &mut Vec<Finding>);
type BadPracticeEntry = (&'static str, BadPracticeFn, &'static RuleMetadata);

const BP_1_META: RuleMetadata = RuleMetadata {
    id: "BP-1",
    title: "Discarded Error Return",
    description: "A returned error is assigned to `_`, suppressing error handling.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("handle the error or explicitly ignore it with a comment"),
};

const BP_2_META: RuleMetadata = RuleMetadata {
    id: "BP-2",
    title: "Naked Error Return",
    description: "An error is returned without wrapping contextual information.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("wrap the error with operation-specific context"),
};

const BP_3_META: RuleMetadata = RuleMetadata {
    id: "BP-3",
    title: "Panic Outside Main Or Test",
    description: "panic is called outside main() or test files.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("return the error up the call stack instead of panicking"),
};

const BP_4_META: RuleMetadata = RuleMetadata {
    id: "BP-4",
    title: "Recover Without Logging",
    description: "recover() is used without recording the recovered panic.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("log or otherwise surface the recovered panic before continuing"),
};

const BP_5_META: RuleMetadata = RuleMetadata {
    id: "BP-5",
    title: "Ignored Close Error",
    description: "Close() is called without checking its returned error.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("check and handle the error returned by Close()"),
};

const BP_6_META: RuleMetadata = RuleMetadata {
    id: "BP-6",
    title: "WaitGroup Add Inside Goroutine",
    description: "sync.WaitGroup.Add is called inside the goroutine it tracks.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("call Add before starting the goroutine"),
};

const BP_7_META: RuleMetadata = RuleMetadata {
    id: "BP-7",
    title: "Mutex Passed By Value",
    description: "sync.Mutex is passed by value, copying lock state.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("pass a pointer to the mutex or embed it in a pointer receiver"),
};

const BP_8_META: RuleMetadata = RuleMetadata {
    id: "BP-8",
    title: "Unlock Deferred On Mutex Copy",
    description: "defer mu.Unlock() is used on a mutex value copy.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("avoid copying mutexes; lock and unlock the original pointer"),
};

const BP_9_META: RuleMetadata = RuleMetadata {
    id: "BP-9",
    title: "Blocking Select Without Timeout",
    description: "select waits without a default branch, timeout, or context cancellation.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("add a default branch, context cancellation, or timeout case"),
};

const BP_10_META: RuleMetadata = RuleMetadata {
    id: "BP-10",
    title: "time.After Inside Loop",
    description: "time.After is called inside a loop, allocating a timer per iteration.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("reuse a time.Timer or time.Ticker outside the loop"),
};

const BP_11_META: RuleMetadata = RuleMetadata {
    id: "BP-11",
    title: "Defer Inside Loop",
    description: "defer is used inside a loop body.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("move cleanup after the loop or use an explicit closure"),
};

const BP_13_META: RuleMetadata = RuleMetadata {
    id: "BP-13",
    title: "Background Context In Library Function",
    description: "context.Background() is used outside main or initialization code.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("accept a context parameter and propagate it through calls"),
};

const BP_15_META: RuleMetadata = RuleMetadata {
    id: "BP-15",
    title: "Recursive sync.Once.Do",
    description: "sync.Once.Do invokes a closure that recursively calls the same Once.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("move recursive initialization outside the sync.Once.Do closure"),
};

const BAD_PRACTICE_RULES: &[BadPracticeEntry] = &[
    ("BP-1", detect_bp_1_discarded_error, &BP_1_META),
    ("BP-2", detect_bp_2_naked_error_return, &BP_2_META),
    ("BP-3", detect_bp_3_panic_outside_main, &BP_3_META),
    ("BP-4", detect_bp_4_recover_without_logging, &BP_4_META),
    ("BP-5", detect_bp_5_ignored_close_error, &BP_5_META),
    (
        "BP-6",
        detect_bp_6_waitgroup_add_inside_goroutine,
        &BP_6_META,
    ),
    ("BP-7", detect_bp_7_mutex_passed_by_value, &BP_7_META),
    ("BP-8", detect_bp_8_defer_unlock_on_mutex_copy, &BP_8_META),
    ("BP-9", detect_bp_9_select_without_escape, &BP_9_META),
    ("BP-10", detect_bp_10_time_after_in_loop, &BP_10_META),
    ("BP-11", detect_bp_11_defer_in_loop, &BP_11_META),
    (
        "BP-13",
        detect_bp_13_background_context_in_library,
        &BP_13_META,
    ),
    ("BP-15", detect_bp_15_recursive_once_do, &BP_15_META),
];

const RULE_IDS: &[&str] = &[
    "BP-1", "BP-2", "BP-3", "BP-4", "BP-5", "BP-6", "BP-7", "BP-8", "BP-9", "BP-10", "BP-11",
    "BP-13", "BP-15",
];

const SCAN_METADATA: RuleMetadata = RuleMetadata {
    id: "BP",
    title: "Go Bad Practices",
    description: "Common Go bad practices that hurt reliability or maintainability.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: None,
};

pub struct GoBadPracticeScan;

impl Rule for GoBadPracticeScan {
    fn metadata(&self) -> RuleMetadata {
        SCAN_METADATA.clone()
    }
}

impl Detector for GoBadPracticeScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        RULE_IDS
    }

    fn metadata_for(&self, rule_id: &str) -> Option<RuleMetadata> {
        BAD_PRACTICE_RULES
            .iter()
            .find(|(id, _, _)| *id == rule_id)
            .map(|(_, _, meta)| (*meta).clone())
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !self.rule_ids().iter().any(|id| ctx.allows(id)) {
            return;
        }
        for (rule_id, detector, _) in BAD_PRACTICE_RULES {
            if ctx.allows(rule_id) {
                let start = out.len();
                detector(unit, out);
                for finding in &mut out[start..] {
                    ctx.apply_finding_overrides(finding);
                }
            }
        }
    }
}
