//! Rule dispatch table and rule-ID list for Go bad-practice detectors.

use crate::core::ParsedUnit;
use crate::rules::Finding;

use super::rules::*;
use super::source_index::SourceIndex;

type BadPracticeFn = fn(&ParsedUnit, &SourceIndex, &mut Vec<Finding>);
type BadPracticeEntry = (&'static str, BadPracticeFn);

pub(crate) const BAD_PRACTICE_RULES: &[BadPracticeEntry] = &[
    ("BP-1", detect_bp_1_discarded_error),
    ("BP-2", detect_bp_2_naked_error_return),
    ("BP-3", detect_bp_3_panic_outside_main),
    ("BP-4", detect_bp_4_recover_without_logging),
    ("BP-5", detect_bp_5_ignored_close_error),
    ("BP-6", detect_bp_6_waitgroup_add_inside_goroutine),
    ("BP-7", detect_bp_7_mutex_passed_by_value),
    ("BP-8", detect_bp_8_defer_unlock_on_mutex_copy),
    ("BP-9", detect_bp_9_select_without_escape),
    ("BP-10", detect_bp_10_time_after_in_loop),
    ("BP-11", detect_bp_11_defer_in_loop),
    ("BP-16", detect_bp_16_time_sleep_in_test),
    ("BP-17", detect_bp_17_t_error_followed_by_t_fatal),
    ("BP-18", detect_bp_18_t_error_without_early_exit),
    ("BP-19", detect_bp_19_missing_t_helper_on_test_helper),
    ("BP-20", detect_bp_20_table_test_without_t_run),
    ("BP-21", detect_bp_21_subtest_missing_t_parallel),
    ("BP-22", detect_bp_22_testmain_without_os_exit),
    ("BP-23", detect_bp_23_missing_testing_short_guard),
    ("BP-24", detect_bp_24_test_file_without_tests),
    ("BP-25", detect_bp_25_test_helper_returns_error),
    ("BP-26", detect_bp_26_context_not_first_parameter),
    ("BP-27", detect_bp_27_exported_function_returns_unexported_type),
    ("BP-28", detect_bp_28_single_method_interface),
    ("BP-29", detect_bp_29_interface_bloat),
    ("BP-30", detect_bp_30_exported_interface_without_same_package_impl),
    ("BP-31", detect_bp_31_constructor_returns_concrete_type),
    ("BP-32", detect_bp_32_string_alias_error_type),
    ("BP-33", detect_bp_33_sentinel_error_without_is_method),
    ("BP-34", detect_bp_34_error_wrapping_without_percent_w),
    ("BP-35", detect_bp_35_package_name_directory_mismatch),
    ("BP-36", detect_bp_36_init_with_side_effects),
    ("BP-37", detect_bp_37_package_level_mutable_global),
    ("BP-38", detect_bp_38_unused_unexported_helper),
    ("BP-39", detect_bp_39_exported_function_without_doc_comment),
    ("BP-40", detect_bp_40_unrelated_constants_in_one_block),
    ("BP-41", detect_bp_41_missing_package_doc_comment),
    ("BP-42", detect_bp_42_one_off_import_alias),
    ("BP-43", detect_bp_43_dot_import_outside_tests),
    ("BP-44", detect_bp_44_blank_import_without_justification),
    ("BP-45", detect_bp_45_inconsistent_receiver_name),
    ("BP-46", detect_bp_46_http_server_missing_timeouts),
    ("BP-47", detect_bp_47_no_graceful_shutdown),
    ("BP-48", detect_bp_48_process_exit_in_library_code),
    ("BP-49", detect_bp_49_deferred_cleanup_without_error_handling),
    ("BP-50", detect_bp_50_no_signal_handling_for_server),
    ("BP-51", detect_bp_51_recover_without_repanic_in_library),
    ("BP-56", detect_bp_56_deprecated_package_used),
    ("BP-58", detect_bp_58_unpinned_dependency_version),
    ("BP-59", detect_bp_59_unused_direct_dependency),
    ("BP-60", detect_bp_60_test_only_dependency_in_main_go_mod),
    ("BP-64", detect_bp_64_replace_directive_local_filesystem),
    ("BP-65", detect_bp_65_missing_go_sum_entries),
    ("BP-13", detect_bp_13_background_context_in_library),
    ("BP-15", detect_bp_15_recursive_once_do),
];

pub(crate) const RULE_IDS: &[&str] = &[
    "BP-1", "BP-2", "BP-3", "BP-4", "BP-5", "BP-6", "BP-7", "BP-8", "BP-9", "BP-10", "BP-11",
    "BP-13", "BP-15", "BP-16", "BP-17", "BP-18", "BP-19", "BP-20", "BP-21", "BP-22", "BP-23",
    "BP-24", "BP-25", "BP-26", "BP-27", "BP-28", "BP-29", "BP-30", "BP-31", "BP-32", "BP-33",
    "BP-34", "BP-35", "BP-36", "BP-37", "BP-38", "BP-39", "BP-40", "BP-41", "BP-42", "BP-43",
    "BP-44", "BP-45", "BP-46", "BP-47", "BP-48", "BP-49", "BP-50", "BP-51", "BP-56", "BP-58",
    "BP-59", "BP-60", "BP-64", "BP-65",
];
