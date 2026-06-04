//! Go CWE detector regression tests.

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn cwe_15_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-15-vulnerable.txt", &["CWE-15"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-15-safe.txt", &[]);
}

#[test]
fn cwe_22_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-22-vulnerable.txt", &["CWE-22"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-22-safe.txt", &[]);
}

#[test]
fn cwe_41_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-41-vulnerable.txt", &["CWE-41"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-41-safe.txt", &[]);
}

#[test]
fn cwe_59_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-59-vulnerable.txt", &["CWE-59"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-59-safe.txt", &[]);
}

#[test]
fn cwe_76_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-76-vulnerable.txt", &["CWE-76"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-76-safe.txt", &[]);
}

#[test]
fn cwe_78_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-78-vulnerable.txt", &["CWE-78"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-78-safe.txt", &[]);
}

#[test]
fn cwe_79_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-79-vulnerable.txt", &["CWE-79"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-79-safe.txt", &[]);
}

#[test]
fn cwe_89_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-89-vulnerable.txt", &["CWE-89"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-89-safe.txt", &[]);
}

#[test]
fn cwe_90_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-90-vulnerable.txt", &["CWE-90"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-90-safe.txt", &[]);
}

#[test]
fn cwe_91_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-91-vulnerable.txt", &["CWE-91"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-91-safe.txt", &[]);
}

#[test]
fn cwe_93_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-93-vulnerable.txt", &["CWE-93"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-93-safe.txt", &[]);
}

#[test]
fn cwe_112_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-112-vulnerable.txt", &["CWE-112"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-112-safe.txt", &[]);
}

#[test]
fn cwe_140_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-140-vulnerable.txt", &["CWE-140"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-140-safe.txt", &[]);
}

#[test]
fn cwe_178_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-178-vulnerable.txt", &["CWE-178"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-178-safe.txt", &[]);
}

#[test]
fn cwe_179_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-179-vulnerable.txt", &["CWE-179"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-179-safe.txt", &[]);
}

#[test]
fn cwe_182_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-182-vulnerable.txt", &["CWE-182"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-182-safe.txt", &[]);
}

#[test]
fn cwe_184_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-184-vulnerable.txt", &["CWE-184"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-184-safe.txt", &[]);
}

#[test]
fn cwe_186_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-186-vulnerable.txt", &["CWE-186"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-186-safe.txt", &[]);
}

#[test]
fn cwe_201_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-201-vulnerable.txt", &["CWE-201"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-201-safe.txt", &[]);
}

#[test]
fn cwe_204_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-204-vulnerable.txt", &["CWE-204"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-204-safe.txt", &[]);
}

#[test]
fn cwe_208_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-208-vulnerable.txt", &["CWE-208"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-208-safe.txt", &[]);
}

#[test]
fn cwe_209_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-209-vulnerable.txt", &["CWE-209"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-209-safe.txt", &[]);
}

#[test]
fn cwe_212_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-212-vulnerable.txt", &["CWE-212"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-212-safe.txt", &[]);
}

#[test]
fn cwe_213_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-213-vulnerable.txt", &["CWE-213"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-213-safe.txt", &[]);
}

#[test]
fn cwe_214_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-214-vulnerable.txt", &["CWE-214"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-214-safe.txt", &[]);
}

#[test]
fn cwe_215_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-215-vulnerable.txt", &["CWE-215"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-215-safe.txt", &[]);
}

#[test]
fn cwe_250_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-250-vulnerable.txt", &["CWE-250"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-250-safe.txt", &[]);
}

#[test]
fn cwe_252_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-252-vulnerable.txt", &["CWE-252"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-252-safe.txt", &[]);
}

#[test]
fn cwe_256_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-256-vulnerable.txt", &["CWE-256"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-256-safe.txt", &[]);
}

#[test]
fn cwe_257_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-257-vulnerable.txt", &["CWE-257"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-257-safe.txt", &[]);
}

#[test]
fn cwe_260_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-260-vulnerable.txt", &["CWE-260"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-260-safe.txt", &[]);
}

#[test]
fn cwe_261_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-261-vulnerable.txt", &["CWE-261"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-261-safe.txt", &[]);
}

#[test]
fn cwe_262_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-262-vulnerable.txt", &["CWE-262"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-262-safe.txt", &[]);
}

#[test]
fn cwe_263_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-263-vulnerable.txt", &["CWE-263"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-263-safe.txt", &[]);
}

#[test]
fn cwe_266_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-266-vulnerable.txt", &["CWE-266"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-266-safe.txt", &[]);
}

#[test]
fn cwe_267_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-267-vulnerable.txt", &["CWE-267"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-267-safe.txt", &[]);
}

#[test]
fn cwe_268_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-268-vulnerable.txt", &["CWE-268"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-268-safe.txt", &[]);
}

#[test]
fn cwe_270_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-270-vulnerable.txt", &["CWE-270"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-270-safe.txt", &[]);
}

#[test]
fn cwe_272_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-272-vulnerable.txt", &["CWE-272"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-272-safe.txt", &[]);
}

#[test]
fn cwe_273_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-273-vulnerable.txt", &["CWE-273"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-273-safe.txt", &[]);
}

#[test]
fn cwe_274_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-274-vulnerable.txt", &["CWE-274"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-274-safe.txt", &[]);
}

#[test]
fn cwe_276_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-276-vulnerable.txt", &["CWE-276"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-276-safe.txt", &[]);
}

#[test]
fn cwe_277_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-277-vulnerable.txt", &["CWE-277"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-277-safe.txt", &[]);
}

#[test]
fn cwe_278_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-278-vulnerable.txt", &["CWE-278"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-278-safe.txt", &[]);
}

#[test]
fn cwe_279_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-279-vulnerable.txt", &["CWE-279"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-279-safe.txt", &[]);
}

#[test]
fn cwe_280_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-280-vulnerable.txt", &["CWE-280"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-280-safe.txt", &[]);
}

#[test]
fn cwe_281_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-281-vulnerable.txt", &["CWE-281"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-281-safe.txt", &[]);
}

#[test]
fn cwe_283_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-283-vulnerable.txt", &["CWE-283"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-283-safe.txt", &[]);
}

#[test]
fn cwe_289_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-289-vulnerable.txt", &["CWE-289"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-289-safe.txt", &[]);
}

#[test]
fn cwe_290_framework_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-290-vulnerable.txt", &["CWE-290"]);
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-290-safe.txt", &[]);
}

#[test]
fn cwe_15_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-15-vulnerable.txt", &["CWE-15"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-15-safe.txt", &[]);
}

#[test]
fn cwe_22_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-22-vulnerable.txt", &["CWE-22"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-22-safe.txt", &[]);
}

#[test]
fn cwe_41_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-41-vulnerable.txt", &["CWE-41"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-41-safe.txt", &[]);
}

#[test]
fn cwe_59_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-59-vulnerable.txt", &["CWE-59"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-59-safe.txt", &[]);
}

#[test]
fn cwe_76_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-76-vulnerable.txt", &["CWE-76"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-76-safe.txt", &[]);
}

#[test]
fn cwe_78_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-78-vulnerable.txt", &["CWE-78"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-78-safe.txt", &[]);
}

#[test]
fn cwe_79_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-79-vulnerable.txt", &["CWE-79"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-79-safe.txt", &[]);
}

#[test]
fn cwe_89_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-89-vulnerable.txt", &["CWE-89"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-89-safe.txt", &[]);
}

#[test]
fn cwe_90_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-90-vulnerable.txt", &["CWE-90"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-90-safe.txt", &[]);
}

#[test]
fn cwe_91_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-91-vulnerable.txt", &["CWE-91"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-91-safe.txt", &[]);
}

#[test]
fn cwe_93_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-93-vulnerable.txt", &["CWE-93"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-93-safe.txt", &[]);
}

#[test]
fn cwe_112_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-112-vulnerable.txt", &["CWE-112"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-112-safe.txt", &[]);
}

#[test]
fn cwe_140_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-140-vulnerable.txt", &["CWE-140"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-140-safe.txt", &[]);
}

#[test]
fn cwe_178_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-178-vulnerable.txt", &["CWE-178"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-178-safe.txt", &[]);
}

#[test]
fn cwe_179_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-179-vulnerable.txt", &["CWE-179"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-179-safe.txt", &[]);
}

#[test]
fn cwe_182_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-182-vulnerable.txt", &["CWE-182"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-182-safe.txt", &[]);
}

#[test]
fn cwe_184_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-184-vulnerable.txt", &["CWE-184"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-184-safe.txt", &[]);
}

#[test]
fn cwe_186_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-186-vulnerable.txt", &["CWE-186"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-186-safe.txt", &[]);
}

#[test]
fn cwe_201_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-201-vulnerable.txt", &["CWE-201"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-201-safe.txt", &[]);
}

#[test]
fn cwe_204_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-204-vulnerable.txt", &["CWE-204"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-204-safe.txt", &[]);
}

#[test]
fn cwe_208_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-208-vulnerable.txt", &["CWE-208"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-208-safe.txt", &[]);
}

#[test]
fn cwe_209_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-209-vulnerable.txt", &["CWE-209"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-209-safe.txt", &[]);
}

#[test]
fn cwe_212_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-212-vulnerable.txt", &["CWE-212"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-212-safe.txt", &[]);
}

#[test]
fn cwe_213_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-213-vulnerable.txt", &["CWE-213"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-213-safe.txt", &[]);
}

#[test]
fn cwe_214_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-214-vulnerable.txt", &["CWE-214"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-214-safe.txt", &[]);
}

#[test]
fn cwe_215_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-215-vulnerable.txt", &["CWE-215"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-215-safe.txt", &[]);
}

#[test]
fn cwe_250_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-250-vulnerable.txt", &["CWE-250"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-250-safe.txt", &[]);
}

#[test]
fn cwe_252_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-252-vulnerable.txt", &["CWE-252"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-252-safe.txt", &[]);
}

#[test]
fn cwe_256_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-256-vulnerable.txt", &["CWE-256"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-256-safe.txt", &[]);
}

#[test]
fn cwe_257_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-257-vulnerable.txt", &["CWE-257"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-257-safe.txt", &[]);
}

#[test]
fn cwe_260_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-260-vulnerable.txt", &["CWE-260"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-260-safe.txt", &[]);
}

#[test]
fn cwe_261_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-261-vulnerable.txt", &["CWE-261"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-261-safe.txt", &[]);
}

#[test]
fn cwe_262_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-262-vulnerable.txt", &["CWE-262"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-262-safe.txt", &[]);
}

#[test]
fn cwe_263_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-263-vulnerable.txt", &["CWE-263"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-263-safe.txt", &[]);
}

#[test]
fn cwe_266_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-266-vulnerable.txt", &["CWE-266"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-266-safe.txt", &[]);
}

#[test]
fn cwe_267_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-267-vulnerable.txt", &["CWE-267"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-267-safe.txt", &[]);
}

#[test]
fn cwe_268_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-268-vulnerable.txt", &["CWE-268"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-268-safe.txt", &[]);
}

#[test]
fn cwe_270_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-270-vulnerable.txt", &["CWE-270"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-270-safe.txt", &[]);
}

#[test]
fn cwe_272_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-272-vulnerable.txt", &["CWE-272"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-272-safe.txt", &[]);
}

#[test]
fn cwe_273_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-273-vulnerable.txt", &["CWE-273"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-273-safe.txt", &[]);
}

#[test]
fn cwe_274_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-274-vulnerable.txt", &["CWE-274"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-274-safe.txt", &[]);
}

#[test]
fn cwe_276_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-276-vulnerable.txt", &["CWE-276"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-276-safe.txt", &[]);
}

#[test]
fn cwe_277_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-277-vulnerable.txt", &["CWE-277"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-277-safe.txt", &[]);
}

#[test]
fn cwe_278_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-278-vulnerable.txt", &["CWE-278"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-278-safe.txt", &[]);
}

#[test]
fn cwe_279_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-279-vulnerable.txt", &["CWE-279"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-279-safe.txt", &[]);
}

#[test]
fn cwe_280_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-280-vulnerable.txt", &["CWE-280"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-280-safe.txt", &[]);
}

#[test]
fn cwe_281_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-281-vulnerable.txt", &["CWE-281"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-281-safe.txt", &[]);
}

#[test]
fn cwe_283_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-283-vulnerable.txt", &["CWE-283"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-283-safe.txt", &[]);
}

#[test]
fn cwe_289_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-289-vulnerable.txt", &["CWE-289"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-289-safe.txt", &[]);
}

#[test]
fn cwe_290_stdlib_fixture_pair() {
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-290-vulnerable.txt", &["CWE-290"]);
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-290-safe.txt", &[]);
}
