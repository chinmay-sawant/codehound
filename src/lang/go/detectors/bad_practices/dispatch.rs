//! Rule dispatch table and rule-ID list for Go bad-practice detectors.

use std::sync::OnceLock;

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
    (
        "BP-12",
        detect_bp_12_unbuffered_channel_send_from_multiple_goroutines,
    ),
    ("BP-14", detect_bp_14_goroutine_without_context_cancellation),
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
    (
        "BP-27",
        detect_bp_27_exported_function_returns_unexported_type,
    ),
    ("BP-28", detect_bp_28_single_method_interface),
    ("BP-29", detect_bp_29_interface_bloat),
    (
        "BP-30",
        detect_bp_30_exported_interface_without_same_package_impl,
    ),
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
    (
        "BP-49",
        detect_bp_49_deferred_cleanup_without_error_handling,
    ),
    ("BP-50", detect_bp_50_no_signal_handling_for_server),
    ("BP-51", detect_bp_51_recover_without_repanic_in_library),
    ("BP-52", detect_bp_52_unchecked_integer_multiplication),
    ("BP-53", detect_bp_53_gob_registration_mismatch),
    (
        "BP-54",
        detect_bp_54_public_http_endpoint_without_rate_limiting,
    ),
    ("BP-55", detect_bp_55_missing_request_id_propagation),
    ("BP-56", detect_bp_56_deprecated_package_used),
    ("BP-57", detect_bp_57_stale_go_version_in_go_mod),
    ("BP-58", detect_bp_58_unpinned_dependency_version),
    ("BP-59", detect_bp_59_unused_direct_dependency),
    ("BP-60", detect_bp_60_test_only_dependency_in_main_go_mod),
    ("BP-61", detect_bp_61_indirect_dependency_missing_annotation),
    ("BP-62", detect_bp_62_dependency_used_in_one_file),
    ("BP-63", detect_bp_63_dependency_with_known_cve_not_updated),
    ("BP-64", detect_bp_64_replace_directive_local_filesystem),
    ("BP-65", detect_bp_65_missing_go_sum_entries),
    ("BP-72", detect_bp_72_typed_nil_interface_return),
    ("BP-73", detect_bp_73_nil_map_write_without_initialization),
    ("BP-79", detect_bp_79_context_cancel_not_released),
    ("BP-84", detect_bp_84_integer_percentage_truncation),
    ("BP-101", detect_bp_101_http_header_after_body),
    ("BP-67", detect_bp_67_errors_as_target_not_pointer),
    ("BP-75", detect_bp_75_copy_into_zero_length_slice),
    ("BP-80", detect_bp_80_context_todo_in_production),
    ("BP-88", detect_bp_88_nil_channel_operation),
    ("BP-98", detect_bp_98_open_file_without_close),
    ("BP-99", detect_bp_99_cond_wait_without_lock),
    ("BP-109", detect_bp_109_gin_error_response_without_abort),
    ("BP-116", detect_bp_116_echo_response_error_double_handling),
    ("BP-131", detect_bp_131_query_for_exec_only),
    ("BP-145", detect_bp_145_pool_conn_not_released),
    ("BP-159", detect_bp_159_flag_used_before_parse),
    ("BP-68", detect_bp_68_discarded_errors_join),
    ("BP-85", detect_bp_85_unchecked_handler_context_assertion),
    ("BP-102", detect_bp_102_http_error_path_without_status),
    ("BP-136", detect_bp_136_gorm_automigrate_in_request_path),
    ("BP-142", detect_bp_142_sqlx_in_without_rebind),
    ("BP-151", detect_bp_151_secret_env_logged),
    ("BP-162", detect_bp_162_parallel_test_shared_mutation),
    ("BP-164", detect_bp_164_option_mutates_global_default),
    ("BP-66", detect_bp_66_wrapped_error_compared_directly),
    ("BP-86", detect_bp_86_mutex_lock_without_unlock),
    ("BP-87", detect_bp_87_rlock_across_blocking_call),
    ("BP-89", detect_bp_89_repeated_channel_close),
    ("BP-110", detect_bp_110_gin_bind_error_ignored),
    ("BP-117", detect_bp_117_echo_bind_error_ignored),
    ("BP-120", detect_bp_120_fiber_body_parser_error_ignored),
    ("BP-138", detect_bp_138_gorm_hook_external_call),
    (
        "BP-141",
        detect_bp_141_sqlx_named_struct_without_matching_tag,
    ),
    ("BP-161", detect_bp_161_test_uses_production_dsn),
    ("BP-163", detect_bp_163_unguarded_golden_update),
    ("BP-76", detect_bp_76_map_range_used_for_ordered_output),
    ("BP-81", detect_bp_81_repeated_now_in_condition),
    ("BP-90", detect_bp_90_channel_receive_loop_without_exit),
    ("BP-91", detect_bp_91_data_bearing_notification_channel),
    ("BP-92", detect_bp_92_errgroup_without_context),
    ("BP-93", detect_bp_93_errgroup_closure_discards_error),
    ("BP-94", detect_bp_94_goroutine_map_write_without_sync),
    ("BP-96", detect_bp_96_sql_rows_without_close),
    ("BP-97", detect_bp_97_writer_not_flushed_before_read),
    ("BP-100", detect_bp_100_unbounded_goroutine_fanout),
    ("BP-104", detect_bp_104_http_mux_pattern_overlap),
    ("BP-105", detect_bp_105_http_cookie_security_flags_missing),
    ("BP-107", detect_bp_107_http_middleware_missing_next),
    ("BP-122", detect_bp_122_chi_middleware_missing_next),
    ("BP-128", detect_bp_128_query_row_scan_without_no_rows),
    ("BP-132", detect_bp_132_update_without_rows_affected),
    ("BP-133", detect_bp_133_gorm_chain_error_ignored),
    ("BP-134", detect_bp_134_gorm_first_without_not_found),
    ("BP-135", detect_bp_135_gorm_global_without_session),
    ("BP-140", detect_bp_140_sqlx_error_ignored),
    ("BP-143", detect_bp_143_redis_result_error_ignored),
    ("BP-146", detect_bp_146_sensitive_fields_logged),
    ("BP-147", detect_bp_147_unstructured_service_logging),
    ("BP-149", detect_bp_149_error_log_without_attribute),
    ("BP-155", detect_bp_155_unbounded_json_request_body),
    ("BP-156", detect_bp_156_sensitive_json_omitempty),
    ("BP-70", detect_bp_70_logging_error_then_continuing),
    ("BP-82", detect_bp_82_time_parse_without_location),
    ("BP-83", detect_bp_83_sleep_for_synchronization),
    ("BP-95", detect_bp_95_http_response_body_not_closed),
    ("BP-111", detect_bp_111_gin_context_in_goroutine),
    ("BP-119", detect_bp_119_fiber_context_in_goroutine),
    ("BP-126", detect_bp_126_transaction_without_commit_rollback),
    ("BP-154", detect_bp_154_json_unmarshal_error_ignored),
    ("BP-158", detect_bp_158_grpc_error_handling),
    ("BP-160", detect_bp_160_cobra_run_without_run_e),
    ("BP-13", detect_bp_13_background_context_in_library),
    ("BP-15", detect_bp_15_recursive_once_do),
];

pub(crate) fn rule_ids() -> &'static [&'static str] {
    static IDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    IDS.get_or_init(|| BAD_PRACTICE_RULES.iter().map(|(id, _)| *id).collect())
        .as_slice()
}

/// Go-module hygiene rules emit once per project, on its anchor file.
///
/// Keeping this classification beside the dispatch table lets the scan skip all
/// nine detector calls for non-anchor files, rather than asking each rule to
/// rediscover the same project anchor independently.
pub(crate) fn requires_project_anchor(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "BP-57" | "BP-58" | "BP-59" | "BP-60" | "BP-61" | "BP-62" | "BP-63" | "BP-64" | "BP-65"
    )
}

/// Server-policy rules emit once on the executable server entrypoint rather
/// than on an arbitrary file in the project.
pub(crate) fn requires_server_anchor(rule_id: &str) -> bool {
    matches!(rule_id, "BP-47" | "BP-50" | "BP-54" | "BP-55")
}

#[cfg(test)]
mod tests {
    use super::{requires_project_anchor, requires_server_anchor};

    #[test]
    fn requires_project_anchor_only_for_go_module_hygiene_rules() {
        assert!(requires_project_anchor("BP-57"));
        assert!(requires_project_anchor("BP-65"));
        assert!(!requires_project_anchor("BP-56"));
        assert!(!requires_project_anchor("BP-66"));
    }

    #[test]
    fn requires_server_anchor_only_for_server_policy_rules() {
        assert!(requires_server_anchor("BP-47"));
        assert!(requires_server_anchor("BP-55"));
        assert!(!requires_server_anchor("BP-46"));
        assert!(!requires_server_anchor("BP-57"));
    }
}
