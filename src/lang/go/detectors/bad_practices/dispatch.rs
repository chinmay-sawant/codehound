//! Rule dispatch table and rule-ID list for Go bad-practice detectors.

use crate::core::ParsedUnit;
use crate::rules::{Finding, RuleMetadata};

use super::rules::*;
use super::source_index::SourceIndex;

type BadPracticeFn = fn(&ParsedUnit, &SourceIndex, &mut Vec<Finding>);
type BadPracticeEntry = (&'static str, BadPracticeFn, &'static RuleMetadata);

pub(crate) const BAD_PRACTICE_RULES: &[BadPracticeEntry] = &[
    ("BP-1", detect_bp_1_discarded_error, &super::BP_1_META),
    ("BP-2", detect_bp_2_naked_error_return, &super::BP_2_META),
    ("BP-3", detect_bp_3_panic_outside_main, &super::BP_3_META),
    (
        "BP-4",
        detect_bp_4_recover_without_logging,
        &super::BP_4_META,
    ),
    ("BP-5", detect_bp_5_ignored_close_error, &super::BP_5_META),
    (
        "BP-6",
        detect_bp_6_waitgroup_add_inside_goroutine,
        &super::BP_6_META,
    ),
    ("BP-7", detect_bp_7_mutex_passed_by_value, &super::BP_7_META),
    (
        "BP-8",
        detect_bp_8_defer_unlock_on_mutex_copy,
        &super::BP_8_META,
    ),
    ("BP-9", detect_bp_9_select_without_escape, &super::BP_9_META),
    ("BP-10", detect_bp_10_time_after_in_loop, &super::BP_10_META),
    ("BP-11", detect_bp_11_defer_in_loop, &super::BP_11_META),
    (
        "BP-13",
        detect_bp_13_background_context_in_library,
        &super::BP_13_META,
    ),
    ("BP-15", detect_bp_15_recursive_once_do, &super::BP_15_META),
];

pub(crate) const RULE_IDS: &[&str] = &[
    "BP-1", "BP-2", "BP-3", "BP-4", "BP-5", "BP-6", "BP-7", "BP-8", "BP-9", "BP-10", "BP-11",
    "BP-13", "BP-15",
];
