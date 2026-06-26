//! Rule metadata constants for Go bad-practice detectors.

use crate::cwe::CweRef;
use crate::rules::{RuleMetadata, Severity};

pub(crate) const BP_1_META: RuleMetadata = RuleMetadata {
    id: "BP-1",
    title: "Discarded Error Return",
    description: "A returned error is assigned to `_`, suppressing error handling.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("handle the error or explicitly ignore it with a comment"),
};

pub(crate) const BP_2_META: RuleMetadata = RuleMetadata {
    id: "BP-2",
    title: "Naked Error Return",
    description: "An error is returned without wrapping contextual information.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("wrap the error with operation-specific context"),
};

pub(crate) const BP_3_META: RuleMetadata = RuleMetadata {
    id: "BP-3",
    title: "Panic Outside Main Or Test",
    description: "panic is called outside main() or test files.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("return the error up the call stack instead of panicking"),
};

pub(crate) const BP_4_META: RuleMetadata = RuleMetadata {
    id: "BP-4",
    title: "Recover Without Logging",
    description: "recover() is used without recording the recovered panic.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("log or otherwise surface the recovered panic before continuing"),
};

pub(crate) const BP_5_META: RuleMetadata = RuleMetadata {
    id: "BP-5",
    title: "Ignored Close Error",
    description: "Close() is called without checking its returned error.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("check and handle the error returned by Close()"),
};

pub(crate) const BP_6_META: RuleMetadata = RuleMetadata {
    id: "BP-6",
    title: "WaitGroup Add Inside Goroutine",
    description: "sync.WaitGroup.Add is called inside the goroutine it tracks.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("call Add before starting the goroutine"),
};

pub(crate) const BP_7_META: RuleMetadata = RuleMetadata {
    id: "BP-7",
    title: "Mutex Passed By Value",
    description: "sync.Mutex is passed by value, copying lock state.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("pass a pointer to the mutex or embed it in a pointer receiver"),
};

pub(crate) const BP_8_META: RuleMetadata = RuleMetadata {
    id: "BP-8",
    title: "Unlock Deferred On Mutex Copy",
    description: "defer mu.Unlock() is used on a mutex value copy.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("avoid copying mutexes; lock and unlock the original pointer"),
};

pub(crate) const BP_9_META: RuleMetadata = RuleMetadata {
    id: "BP-9",
    title: "Blocking Select Without Timeout",
    description: "select waits without a default branch, timeout, or context cancellation.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("add a default branch, context cancellation, or timeout case"),
};

pub(crate) const BP_10_META: RuleMetadata = RuleMetadata {
    id: "BP-10",
    title: "time.After Inside Loop",
    description: "time.After is called inside a loop, allocating a timer per iteration.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("reuse a time.Timer or time.Ticker outside the loop"),
};

pub(crate) const BP_11_META: RuleMetadata = RuleMetadata {
    id: "BP-11",
    title: "Defer Inside Loop",
    description: "defer is used inside a loop body.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("move cleanup after the loop or use an explicit closure"),
};

pub(crate) const BP_13_META: RuleMetadata = RuleMetadata {
    id: "BP-13",
    title: "Background Context In Library Function",
    description: "context.Background() is used outside main or initialization code.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("accept a context parameter and propagate it through calls"),
};

pub(crate) const BP_15_META: RuleMetadata = RuleMetadata {
    id: "BP-15",
    title: "Recursive sync.Once.Do",
    description: "sync.Once.Do invokes a closure that recursively calls the same Once.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: Some("move recursive initialization outside the sync.Once.Do closure"),
};

pub(crate) const SCAN_METADATA: RuleMetadata = RuleMetadata {
    id: "BP",
    title: "Go Bad Practices",
    description: "Common Go bad practices that hurt reliability or maintainability.",
    severity: Severity::Low,
    cwe: &[] as &'static [CweRef],
    fix: None,
};
