//! Go CWE detector regression tests.

#[path = "helpers/mod.rs"]
mod helpers;

#[test]
fn cwe_15_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-15-vulnerable.txt",
        &["CWE-15"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-15-safe.txt", &[]);
}

#[test]
fn cwe_22_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-22-vulnerable.txt",
        &["CWE-22"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-22-safe.txt", &[]);
}

#[test]
fn cwe_41_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-41-vulnerable.txt",
        &["CWE-41"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-41-safe.txt", &[]);
}

#[test]
fn cwe_59_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-59-vulnerable.txt",
        &["CWE-59"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-59-safe.txt", &[]);
}

#[test]
fn cwe_76_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-76-vulnerable.txt",
        &["CWE-76"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-76-safe.txt", &[]);
}

#[test]
fn cwe_78_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-78-vulnerable.txt",
        &["CWE-78"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-78-safe.txt", &[]);
}

#[test]
fn cwe_79_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-79-vulnerable.txt",
        &["CWE-79"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-79-safe.txt", &[]);
}

#[test]
fn cwe_89_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-89-vulnerable.txt",
        &["CWE-89"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-89-safe.txt", &[]);
}

#[test]
fn cwe_90_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-90-vulnerable.txt",
        &["CWE-90"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-90-safe.txt", &[]);
}

#[test]
fn cwe_91_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-91-vulnerable.txt",
        &["CWE-91"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-91-safe.txt", &[]);
}

#[test]
fn cwe_93_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-93-vulnerable.txt",
        &["CWE-93"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-93-safe.txt", &[]);
}

#[test]
fn cwe_112_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-112-vulnerable.txt",
        &["CWE-112"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-112-safe.txt", &[]);
}

#[test]
fn cwe_140_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-140-vulnerable.txt",
        &["CWE-140"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-140-safe.txt", &[]);
}

#[test]
fn cwe_178_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-178-vulnerable.txt",
        &["CWE-178"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-178-safe.txt", &[]);
}

#[test]
fn cwe_179_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-179-vulnerable.txt",
        &["CWE-179"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-179-safe.txt", &[]);
}

#[test]
fn cwe_182_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-182-vulnerable.txt",
        &["CWE-182"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-182-safe.txt", &[]);
}

#[test]
fn cwe_184_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-184-vulnerable.txt",
        &["CWE-184"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-184-safe.txt", &[]);
}

#[test]
fn cwe_186_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-186-vulnerable.txt",
        &["CWE-186"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-186-safe.txt", &[]);
}

#[test]
fn cwe_201_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-201-vulnerable.txt",
        &["CWE-201"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-201-safe.txt", &[]);
}

#[test]
fn cwe_204_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-204-vulnerable.txt",
        &["CWE-204"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-204-safe.txt", &[]);
}

#[test]
fn cwe_208_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-208-vulnerable.txt",
        &["CWE-208"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-208-safe.txt", &[]);
}

#[test]
fn cwe_209_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-209-vulnerable.txt",
        &["CWE-209"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-209-safe.txt", &[]);
}

#[test]
fn cwe_212_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-212-vulnerable.txt",
        &["CWE-212"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-212-safe.txt", &[]);
}

#[test]
fn cwe_213_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-213-vulnerable.txt",
        &["CWE-213"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-213-safe.txt", &[]);
}

#[test]
fn cwe_214_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-214-vulnerable.txt",
        &["CWE-214"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-214-safe.txt", &[]);
}

#[test]
fn cwe_215_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-215-vulnerable.txt",
        &["CWE-215"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-215-safe.txt", &[]);
}

#[test]
fn cwe_250_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-250-vulnerable.txt",
        &["CWE-250"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-250-safe.txt", &[]);
}

#[test]
fn cwe_252_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-252-vulnerable.txt",
        &["CWE-252"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-252-safe.txt", &[]);
}

#[test]
fn cwe_256_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-256-vulnerable.txt",
        &["CWE-256"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-256-safe.txt", &[]);
}

#[test]
fn cwe_257_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-257-vulnerable.txt",
        &["CWE-257"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-257-safe.txt", &[]);
}

#[test]
fn cwe_260_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-260-vulnerable.txt",
        &["CWE-260"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-260-safe.txt", &[]);
}

#[test]
fn cwe_261_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-261-vulnerable.txt",
        &["CWE-261"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-261-safe.txt", &[]);
}

#[test]
fn cwe_262_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-262-vulnerable.txt",
        &["CWE-262"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-262-safe.txt", &[]);
}

#[test]
fn cwe_263_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-263-vulnerable.txt",
        &["CWE-263"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-263-safe.txt", &[]);
}

#[test]
fn cwe_266_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-266-vulnerable.txt",
        &["CWE-266"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-266-safe.txt", &[]);
}

#[test]
fn cwe_267_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-267-vulnerable.txt",
        &["CWE-267"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-267-safe.txt", &[]);
}

#[test]
fn cwe_268_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-268-vulnerable.txt",
        &["CWE-268"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-268-safe.txt", &[]);
}

#[test]
fn cwe_270_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-270-vulnerable.txt",
        &["CWE-270"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-270-safe.txt", &[]);
}

#[test]
fn cwe_272_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-272-vulnerable.txt",
        &["CWE-272"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-272-safe.txt", &[]);
}

#[test]
fn cwe_273_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-273-vulnerable.txt",
        &["CWE-273"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-273-safe.txt", &[]);
}

#[test]
fn cwe_274_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-274-vulnerable.txt",
        &["CWE-274"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-274-safe.txt", &[]);
}

#[test]
fn cwe_276_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-276-vulnerable.txt",
        &["CWE-276"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-276-safe.txt", &[]);
}

#[test]
fn cwe_277_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-277-vulnerable.txt",
        &["CWE-277"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-277-safe.txt", &[]);
}

#[test]
fn cwe_278_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-278-vulnerable.txt",
        &["CWE-278"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-278-safe.txt", &[]);
}

#[test]
fn cwe_279_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-279-vulnerable.txt",
        &["CWE-279"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-279-safe.txt", &[]);
}

#[test]
fn cwe_280_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-280-vulnerable.txt",
        &["CWE-280"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-280-safe.txt", &[]);
}

#[test]
fn cwe_281_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-281-vulnerable.txt",
        &["CWE-281"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-281-safe.txt", &[]);
}

#[test]
fn cwe_283_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-283-vulnerable.txt",
        &["CWE-283"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-283-safe.txt", &[]);
}

#[test]
fn cwe_289_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-289-vulnerable.txt",
        &["CWE-289"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-289-safe.txt", &[]);
}

#[test]
fn cwe_290_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-290-vulnerable.txt",
        &["CWE-290"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-290-safe.txt", &[]);
}

#[test]
fn cwe_294_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-294-vulnerable.txt",
        &["CWE-294"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-294-safe.txt", &[]);
}

#[test]
fn cwe_301_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-301-vulnerable.txt",
        &["CWE-301"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-301-safe.txt", &[]);
}

#[test]
fn cwe_303_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-303-vulnerable.txt",
        &["CWE-303"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-303-safe.txt", &[]);
}

#[test]
fn cwe_305_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-305-vulnerable.txt",
        &["CWE-305"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-305-safe.txt", &[]);
}

#[test]
fn cwe_306_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-306-vulnerable.txt",
        &["CWE-306"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-306-safe.txt", &[]);
}

#[test]
fn cwe_307_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-307-vulnerable.txt",
        &["CWE-307"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-307-safe.txt", &[]);
}

#[test]
fn cwe_308_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-308-vulnerable.txt",
        &["CWE-308"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-308-safe.txt", &[]);
}

#[test]
fn cwe_309_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-309-vulnerable.txt",
        &["CWE-309"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-309-safe.txt", &[]);
}

#[test]
fn cwe_312_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-312-vulnerable.txt",
        &["CWE-312"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-312-safe.txt", &[]);
}

#[test]
fn cwe_319_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-319-vulnerable.txt",
        &["CWE-319"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-319-safe.txt", &[]);
}

#[test]
fn cwe_322_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-322-vulnerable.txt",
        &["CWE-322"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-322-safe.txt", &[]);
}

#[test]
fn cwe_323_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-323-vulnerable.txt",
        &["CWE-323"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-323-safe.txt", &[]);
}

#[test]
fn cwe_324_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-324-vulnerable.txt",
        &["CWE-324"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-324-safe.txt", &[]);
}

#[test]
fn cwe_325_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-325-vulnerable.txt",
        &["CWE-325"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-325-safe.txt", &[]);
}

#[test]
fn cwe_328_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-328-vulnerable.txt",
        &["CWE-328"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-328-safe.txt", &[]);
}

#[test]
fn cwe_331_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-331-vulnerable.txt",
        &["CWE-331"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-331-safe.txt", &[]);
}

#[test]
fn cwe_334_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-334-vulnerable.txt",
        &["CWE-334"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-334-safe.txt", &[]);
}

#[test]
fn cwe_335_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-335-vulnerable.txt",
        &["CWE-335"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-335-safe.txt", &[]);
}

#[test]
fn cwe_338_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-338-vulnerable.txt",
        &["CWE-338"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-338-safe.txt", &[]);
}

#[test]
fn cwe_341_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-341-vulnerable.txt",
        &["CWE-341"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-341-safe.txt", &[]);
}

#[test]
fn cwe_342_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-342-vulnerable.txt",
        &["CWE-342"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-342-safe.txt", &[]);
}

#[test]
fn cwe_343_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-343-vulnerable.txt",
        &["CWE-343"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-343-safe.txt", &[]);
}

#[test]
fn cwe_344_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-344-vulnerable.txt",
        &["CWE-344"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-344-safe.txt", &[]);
}

#[test]
fn cwe_346_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-346-vulnerable.txt",
        &["CWE-346"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-346-safe.txt", &[]);
}

#[test]
fn cwe_347_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-347-vulnerable.txt",
        &["CWE-347"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-347-safe.txt", &[]);
}

#[test]
fn cwe_349_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-349-vulnerable.txt",
        &["CWE-349"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-349-safe.txt", &[]);
}

#[test]
fn cwe_353_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-353-vulnerable.txt",
        &["CWE-353"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-353-safe.txt", &[]);
}

#[test]
fn cwe_356_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-356-vulnerable.txt",
        &["CWE-356"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-356-safe.txt", &[]);
}

#[test]
fn cwe_358_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-358-vulnerable.txt",
        &["CWE-358"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-358-safe.txt", &[]);
}

#[test]
fn cwe_359_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-359-vulnerable.txt",
        &["CWE-359"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-359-safe.txt", &[]);
}

#[test]
fn cwe_360_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-360-vulnerable.txt",
        &["CWE-360"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-360-safe.txt", &[]);
}

#[test]
fn cwe_366_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-366-vulnerable.txt",
        &["CWE-366"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-366-safe.txt", &[]);
}

#[test]
fn cwe_367_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-367-vulnerable.txt",
        &["CWE-367"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-367-safe.txt", &[]);
}

#[test]
fn cwe_368_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-368-vulnerable.txt",
        &["CWE-368"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-368-safe.txt", &[]);
}

#[test]
fn cwe_378_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-378-vulnerable.txt",
        &["CWE-378"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-378-safe.txt", &[]);
}

#[test]
fn cwe_379_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-379-vulnerable.txt",
        &["CWE-379"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-379-safe.txt", &[]);
}

#[test]
fn cwe_385_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-385-vulnerable.txt",
        &["CWE-385"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-385-safe.txt", &[]);
}

#[test]
fn cwe_393_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-393-vulnerable.txt",
        &["CWE-393"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-393-safe.txt", &[]);
}

#[test]
fn cwe_403_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-403-vulnerable.txt",
        &["CWE-403"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-403-safe.txt", &[]);
}

#[test]
fn cwe_408_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-408-vulnerable.txt",
        &["CWE-408"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-408-safe.txt", &[]);
}

#[test]
fn cwe_412_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-412-vulnerable.txt",
        &["CWE-412"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-412-safe.txt", &[]);
}

#[test]
fn cwe_420_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-420-vulnerable.txt",
        &["CWE-420"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-420-safe.txt", &[]);
}

#[test]
fn cwe_421_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-421-vulnerable.txt",
        &["CWE-421"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-421-safe.txt", &[]);
}

#[test]
fn cwe_425_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-425-vulnerable.txt",
        &["CWE-425"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-425-safe.txt", &[]);
}

#[test]
fn cwe_426_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-426-vulnerable.txt",
        &["CWE-426"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-426-safe.txt", &[]);
}

#[test]
fn cwe_427_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-427-vulnerable.txt",
        &["CWE-427"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-427-safe.txt", &[]);
}

#[test]
fn cwe_434_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-434-vulnerable.txt",
        &["CWE-434"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-434-safe.txt", &[]);
}

#[test]
fn cwe_454_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-454-vulnerable.txt",
        &["CWE-454"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-454-safe.txt", &[]);
}

#[test]
fn cwe_455_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-455-vulnerable.txt",
        &["CWE-455"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-455-safe.txt", &[]);
}

#[test]
fn cwe_459_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-459-vulnerable.txt",
        &["CWE-459"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-459-safe.txt", &[]);
}

#[test]
fn cwe_472_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-472-vulnerable.txt",
        &["CWE-472"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-472-safe.txt", &[]);
}

#[test]
fn cwe_488_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-488-vulnerable.txt",
        &["CWE-488"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-488-safe.txt", &[]);
}

#[test]
fn cwe_494_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-494-vulnerable.txt",
        &["CWE-494"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-494-safe.txt", &[]);
}

#[test]
fn cwe_497_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-497-vulnerable.txt",
        &["CWE-497"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-497-safe.txt", &[]);
}

#[test]
fn cwe_501_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-501-vulnerable.txt",
        &["CWE-501"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-501-safe.txt", &[]);
}

#[test]
fn cwe_502_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-502-vulnerable.txt",
        &["CWE-502"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-502-safe.txt", &[]);
}

#[test]
fn cwe_515_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-515-vulnerable.txt",
        &["CWE-515"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-515-safe.txt", &[]);
}

#[test]
fn cwe_521_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-521-vulnerable.txt",
        &["CWE-521"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-521-safe.txt", &[]);
}

#[test]
fn cwe_523_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-523-vulnerable.txt",
        &["CWE-523"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-523-safe.txt", &[]);
}

#[test]
fn cwe_524_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-524-vulnerable.txt",
        &["CWE-524"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-524-safe.txt", &[]);
}

#[test]
fn cwe_547_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-547-vulnerable.txt",
        &["CWE-547"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-547-safe.txt", &[]);
}

#[test]
fn cwe_538_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-538-vulnerable.txt",
        &["CWE-538"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-538-safe.txt", &[]);
}

#[test]
fn cwe_544_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-544-vulnerable.txt",
        &["CWE-544"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-544-safe.txt", &[]);
}

#[test]
fn cwe_549_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-549-vulnerable.txt",
        &["CWE-549"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-549-safe.txt", &[]);
}

#[test]
fn cwe_551_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-551-vulnerable.txt",
        &["CWE-551"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-551-safe.txt", &[]);
}

#[test]
fn cwe_552_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-552-vulnerable.txt",
        &["CWE-552"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-552-safe.txt", &[]);
}

#[test]
fn cwe_565_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-565-vulnerable.txt",
        &["CWE-565"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-565-safe.txt", &[]);
}

#[test]
fn cwe_601_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-601-vulnerable.txt",
        &["CWE-601"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-601-safe.txt", &[]);
}

#[test]
fn cwe_603_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-603-vulnerable.txt",
        &["CWE-603"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-603-safe.txt", &[]);
}

#[test]
fn cwe_605_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-605-vulnerable.txt",
        &["CWE-605"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-605-safe.txt", &[]);
}

#[test]
fn cwe_611_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-611-vulnerable.txt",
        &["CWE-611"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-611-safe.txt", &[]);
}

#[test]
fn cwe_613_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-613-vulnerable.txt",
        &["CWE-613"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-613-safe.txt", &[]);
}

#[test]
fn cwe_618_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-618-vulnerable.txt",
        &["CWE-618"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-618-safe.txt", &[]);
}

#[test]
fn cwe_619_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-619-vulnerable.txt",
        &["CWE-619"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-619-safe.txt", &[]);
}

#[test]
fn cwe_620_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-620-vulnerable.txt",
        &["CWE-620"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-620-safe.txt", &[]);
}

#[test]
fn cwe_639_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-639-vulnerable.txt",
        &["CWE-639"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-639-safe.txt", &[]);
}

#[test]
fn cwe_640_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-640-vulnerable.txt",
        &["CWE-640"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-640-safe.txt", &[]);
}

#[test]
fn cwe_645_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-645-vulnerable.txt",
        &["CWE-645"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-645-safe.txt", &[]);
}

#[test]
fn cwe_648_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-648-vulnerable.txt",
        &["CWE-648"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-648-safe.txt", &[]);
}

#[test]
fn cwe_649_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-649-vulnerable.txt",
        &["CWE-649"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-649-safe.txt", &[]);
}

#[test]
fn cwe_653_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-653-vulnerable.txt",
        &["CWE-653"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-653-safe.txt", &[]);
}

#[test]
fn cwe_654_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-654-vulnerable.txt",
        &["CWE-654"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-654-safe.txt", &[]);
}

#[test]
fn cwe_656_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-656-vulnerable.txt",
        &["CWE-656"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-656-safe.txt", &[]);
}

#[test]
fn cwe_708_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-708-vulnerable.txt",
        &["CWE-708"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-708-safe.txt", &[]);
}

#[test]
fn cwe_756_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-756-vulnerable.txt",
        &["CWE-756"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-756-safe.txt", &[]);
}

#[test]
fn cwe_765_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-765-vulnerable.txt",
        &["CWE-765"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-765-safe.txt", &[]);
}

#[test]
fn cwe_778_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-778-vulnerable.txt",
        &["CWE-778"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-778-safe.txt", &[]);
}

#[test]
fn cwe_783_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-783-vulnerable.txt",
        &["CWE-783"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-783-safe.txt", &[]);
}

#[test]
fn cwe_798_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-798-vulnerable.txt",
        &["CWE-798"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-798-safe.txt", &[]);
}

#[test]
fn cwe_820_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-820-vulnerable.txt",
        &["CWE-820"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-820-safe.txt", &[]);
}

#[test]
fn cwe_821_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-821-vulnerable.txt",
        &["CWE-821"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-821-safe.txt", &[]);
}

#[test]
fn cwe_826_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-826-vulnerable.txt",
        &["CWE-826"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-826-safe.txt", &[]);
}

#[test]
fn cwe_829_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-829-vulnerable.txt",
        &["CWE-829"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-829-safe.txt", &[]);
}

#[test]
fn cwe_836_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-836-vulnerable.txt",
        &["CWE-836"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-836-safe.txt", &[]);
}

#[test]
fn cwe_838_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-838-vulnerable.txt",
        &["CWE-838"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-838-safe.txt", &[]);
}

#[test]
fn cwe_841_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-841-vulnerable.txt",
        &["CWE-841"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-841-safe.txt", &[]);
}

#[test]
fn cwe_842_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-842-vulnerable.txt",
        &["CWE-842"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-842-safe.txt", &[]);
}

#[test]
fn cwe_909_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-909-vulnerable.txt",
        &["CWE-909"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-909-safe.txt", &[]);
}

#[test]
fn cwe_915_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-915-vulnerable.txt",
        &["CWE-915"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-915-safe.txt", &[]);
}

#[test]
fn cwe_916_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-916-vulnerable.txt",
        &["CWE-916"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-916-safe.txt", &[]);
}

#[test]
fn cwe_917_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-917-vulnerable.txt",
        &["CWE-917"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-917-safe.txt", &[]);
}

#[test]
fn cwe_918_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-918-vulnerable.txt",
        &["CWE-918"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-918-safe.txt", &[]);
}

#[test]
fn cwe_921_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-921-vulnerable.txt",
        &["CWE-921"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-921-safe.txt", &[]);
}

#[test]
fn cwe_807_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-807-vulnerable.txt",
        &["CWE-807"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-807-safe.txt", &[]);
}

#[test]
fn cwe_15_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-15-vulnerable.txt",
        &["CWE-15"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-15-safe.txt", &[]);
}

#[test]
fn cwe_22_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-22-vulnerable.txt",
        &["CWE-22"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-22-safe.txt", &[]);
}

#[test]
fn cwe_41_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-41-vulnerable.txt",
        &["CWE-41"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-41-safe.txt", &[]);
}

#[test]
fn cwe_59_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-59-vulnerable.txt",
        &["CWE-59"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-59-safe.txt", &[]);
}

#[test]
fn cwe_76_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-76-vulnerable.txt",
        &["CWE-76"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-76-safe.txt", &[]);
}

#[test]
fn cwe_78_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-78-vulnerable.txt",
        &["CWE-78"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-78-safe.txt", &[]);
}

#[test]
fn cwe_79_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-79-vulnerable.txt",
        &["CWE-79"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-79-safe.txt", &[]);
}

#[test]
fn cwe_89_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-89-vulnerable.txt",
        &["CWE-89"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-89-safe.txt", &[]);
}

#[test]
fn cwe_90_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-90-vulnerable.txt",
        &["CWE-90"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-90-safe.txt", &[]);
}

#[test]
fn cwe_91_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-91-vulnerable.txt",
        &["CWE-91"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-91-safe.txt", &[]);
}

#[test]
fn cwe_93_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-93-vulnerable.txt",
        &["CWE-93"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-93-safe.txt", &[]);
}

#[test]
fn cwe_112_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-112-vulnerable.txt",
        &["CWE-112"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-112-safe.txt", &[]);
}

#[test]
fn cwe_140_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-140-vulnerable.txt",
        &["CWE-140"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-140-safe.txt", &[]);
}

#[test]
fn cwe_178_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-178-vulnerable.txt",
        &["CWE-178"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-178-safe.txt", &[]);
}

#[test]
fn cwe_179_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-179-vulnerable.txt",
        &["CWE-179"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-179-safe.txt", &[]);
}

#[test]
fn cwe_182_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-182-vulnerable.txt",
        &["CWE-182"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-182-safe.txt", &[]);
}

#[test]
fn cwe_184_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-184-vulnerable.txt",
        &["CWE-184"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-184-safe.txt", &[]);
}

#[test]
fn cwe_186_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-186-vulnerable.txt",
        &["CWE-186"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-186-safe.txt", &[]);
}

#[test]
fn cwe_201_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-201-vulnerable.txt",
        &["CWE-201"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-201-safe.txt", &[]);
}

#[test]
fn cwe_204_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-204-vulnerable.txt",
        &["CWE-204"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-204-safe.txt", &[]);
}

#[test]
fn cwe_208_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-208-vulnerable.txt",
        &["CWE-208"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-208-safe.txt", &[]);
}

#[test]
fn cwe_209_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-209-vulnerable.txt",
        &["CWE-209"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-209-safe.txt", &[]);
}

#[test]
fn cwe_212_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-212-vulnerable.txt",
        &["CWE-212"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-212-safe.txt", &[]);
}

#[test]
fn cwe_213_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-213-vulnerable.txt",
        &["CWE-213"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-213-safe.txt", &[]);
}

#[test]
fn cwe_214_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-214-vulnerable.txt",
        &["CWE-214"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-214-safe.txt", &[]);
}

#[test]
fn cwe_215_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-215-vulnerable.txt",
        &["CWE-215"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-215-safe.txt", &[]);
}

#[test]
fn cwe_250_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-250-vulnerable.txt",
        &["CWE-250"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-250-safe.txt", &[]);
}

#[test]
fn cwe_252_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-252-vulnerable.txt",
        &["CWE-252"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-252-safe.txt", &[]);
}

#[test]
fn cwe_256_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-256-vulnerable.txt",
        &["CWE-256"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-256-safe.txt", &[]);
}

#[test]
fn cwe_257_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-257-vulnerable.txt",
        &["CWE-257"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-257-safe.txt", &[]);
}

#[test]
fn cwe_260_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-260-vulnerable.txt",
        &["CWE-260"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-260-safe.txt", &[]);
}

#[test]
fn cwe_261_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-261-vulnerable.txt",
        &["CWE-261"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-261-safe.txt", &[]);
}

#[test]
fn cwe_262_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-262-vulnerable.txt",
        &["CWE-262"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-262-safe.txt", &[]);
}

#[test]
fn cwe_263_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-263-vulnerable.txt",
        &["CWE-263"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-263-safe.txt", &[]);
}

#[test]
fn cwe_266_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-266-vulnerable.txt",
        &["CWE-266"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-266-safe.txt", &[]);
}

#[test]
fn cwe_267_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-267-vulnerable.txt",
        &["CWE-267"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-267-safe.txt", &[]);
}

#[test]
fn cwe_268_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-268-vulnerable.txt",
        &["CWE-268"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-268-safe.txt", &[]);
}

#[test]
fn cwe_270_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-270-vulnerable.txt",
        &["CWE-270"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-270-safe.txt", &[]);
}

#[test]
fn cwe_272_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-272-vulnerable.txt",
        &["CWE-272"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-272-safe.txt", &[]);
}

#[test]
fn cwe_273_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-273-vulnerable.txt",
        &["CWE-273"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-273-safe.txt", &[]);
}

#[test]
fn cwe_274_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-274-vulnerable.txt",
        &["CWE-274"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-274-safe.txt", &[]);
}

#[test]
fn cwe_276_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-276-vulnerable.txt",
        &["CWE-276"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-276-safe.txt", &[]);
}

#[test]
fn cwe_277_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-277-vulnerable.txt",
        &["CWE-277"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-277-safe.txt", &[]);
}

#[test]
fn cwe_278_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-278-vulnerable.txt",
        &["CWE-278"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-278-safe.txt", &[]);
}

#[test]
fn cwe_279_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-279-vulnerable.txt",
        &["CWE-279"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-279-safe.txt", &[]);
}

#[test]
fn cwe_280_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-280-vulnerable.txt",
        &["CWE-280"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-280-safe.txt", &[]);
}

#[test]
fn cwe_281_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-281-vulnerable.txt",
        &["CWE-281"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-281-safe.txt", &[]);
}

#[test]
fn cwe_283_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-283-vulnerable.txt",
        &["CWE-283"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-283-safe.txt", &[]);
}

#[test]
fn cwe_289_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-289-vulnerable.txt",
        &["CWE-289"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-289-safe.txt", &[]);
}

#[test]
fn cwe_290_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-290-vulnerable.txt",
        &["CWE-290"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-290-safe.txt", &[]);
}

#[test]
fn cwe_294_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-294-vulnerable.txt",
        &["CWE-294"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-294-safe.txt", &[]);
}

#[test]
fn cwe_301_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-301-vulnerable.txt",
        &["CWE-301"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-301-safe.txt", &[]);
}

#[test]
fn cwe_303_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-303-vulnerable.txt",
        &["CWE-303"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-303-safe.txt", &[]);
}

#[test]
fn cwe_305_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-305-vulnerable.txt",
        &["CWE-305"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-305-safe.txt", &[]);
}

#[test]
fn cwe_306_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-306-vulnerable.txt",
        &["CWE-306"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-306-safe.txt", &[]);
}

#[test]
fn cwe_307_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-307-vulnerable.txt",
        &["CWE-307"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-307-safe.txt", &[]);
}

#[test]
fn cwe_308_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-308-vulnerable.txt",
        &["CWE-308"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-308-safe.txt", &[]);
}

#[test]
fn cwe_309_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-309-vulnerable.txt",
        &["CWE-309"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-309-safe.txt", &[]);
}

#[test]
fn cwe_312_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-312-vulnerable.txt",
        &["CWE-312"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-312-safe.txt", &[]);
}

#[test]
fn cwe_319_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-319-vulnerable.txt",
        &["CWE-319"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-319-safe.txt", &[]);
}

#[test]
fn cwe_322_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-322-vulnerable.txt",
        &["CWE-322"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-322-safe.txt", &[]);
}

#[test]
fn cwe_323_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-323-vulnerable.txt",
        &["CWE-323"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-323-safe.txt", &[]);
}

#[test]
fn cwe_324_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-324-vulnerable.txt",
        &["CWE-324"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-324-safe.txt", &[]);
}

#[test]
fn cwe_325_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-325-vulnerable.txt",
        &["CWE-325"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-325-safe.txt", &[]);
}

#[test]
fn cwe_328_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-328-vulnerable.txt",
        &["CWE-328"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-328-safe.txt", &[]);
}

#[test]
fn cwe_331_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-331-vulnerable.txt",
        &["CWE-331"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-331-safe.txt", &[]);
}

#[test]
fn cwe_334_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-334-vulnerable.txt",
        &["CWE-334"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-334-safe.txt", &[]);
}

#[test]
fn cwe_335_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-335-vulnerable.txt",
        &["CWE-335"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-335-safe.txt", &[]);
}

#[test]
fn cwe_338_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-338-vulnerable.txt",
        &["CWE-338"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-338-safe.txt", &[]);
}

#[test]
fn cwe_341_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-341-vulnerable.txt",
        &["CWE-341"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-341-safe.txt", &[]);
}

#[test]
fn cwe_342_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-342-vulnerable.txt",
        &["CWE-342"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-342-safe.txt", &[]);
}

#[test]
fn cwe_343_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-343-vulnerable.txt",
        &["CWE-343"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-343-safe.txt", &[]);
}

#[test]
fn cwe_344_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-344-vulnerable.txt",
        &["CWE-344"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-344-safe.txt", &[]);
}

#[test]
fn cwe_346_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-346-vulnerable.txt",
        &["CWE-346"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-346-safe.txt", &[]);
}

#[test]
fn cwe_347_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-347-vulnerable.txt",
        &["CWE-347"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-347-safe.txt", &[]);
}

#[test]
fn cwe_349_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-349-vulnerable.txt",
        &["CWE-349"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-349-safe.txt", &[]);
}

#[test]
fn cwe_353_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-353-vulnerable.txt",
        &["CWE-353"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-353-safe.txt", &[]);
}

#[test]
fn cwe_356_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-356-vulnerable.txt",
        &["CWE-356"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-356-safe.txt", &[]);
}

#[test]
fn cwe_358_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-358-vulnerable.txt",
        &["CWE-358"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-358-safe.txt", &[]);
}

#[test]
fn cwe_359_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-359-vulnerable.txt",
        &["CWE-359"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-359-safe.txt", &[]);
}

#[test]
fn cwe_360_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-360-vulnerable.txt",
        &["CWE-360"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-360-safe.txt", &[]);
}

#[test]
fn cwe_366_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-366-vulnerable.txt",
        &["CWE-366"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-366-safe.txt", &[]);
}

#[test]
fn cwe_367_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-367-vulnerable.txt",
        &["CWE-367"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-367-safe.txt", &[]);
}

#[test]
fn cwe_368_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-368-vulnerable.txt",
        &["CWE-368"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-368-safe.txt", &[]);
}

#[test]
fn cwe_378_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-378-vulnerable.txt",
        &["CWE-378"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-378-safe.txt", &[]);
}

#[test]
fn cwe_379_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-379-vulnerable.txt",
        &["CWE-379"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-379-safe.txt", &[]);
}

#[test]
fn cwe_385_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-385-vulnerable.txt",
        &["CWE-385"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-385-safe.txt", &[]);
}

#[test]
fn cwe_393_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-393-vulnerable.txt",
        &["CWE-393"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-393-safe.txt", &[]);
}

#[test]
fn cwe_403_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-403-vulnerable.txt",
        &["CWE-403"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-403-safe.txt", &[]);
}

#[test]
fn cwe_408_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-408-vulnerable.txt",
        &["CWE-408"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-408-safe.txt", &[]);
}

#[test]
fn cwe_412_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-412-vulnerable.txt",
        &["CWE-412"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-412-safe.txt", &[]);
}

#[test]
fn cwe_420_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-420-vulnerable.txt",
        &["CWE-420"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-420-safe.txt", &[]);
}

#[test]
fn cwe_421_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-421-vulnerable.txt",
        &["CWE-421"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-421-safe.txt", &[]);
}

#[test]
fn cwe_425_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-425-vulnerable.txt",
        &["CWE-425"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-425-safe.txt", &[]);
}

#[test]
fn cwe_426_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-426-vulnerable.txt",
        &["CWE-426"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-426-safe.txt", &[]);
}

#[test]
fn cwe_427_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-427-vulnerable.txt",
        &["CWE-427"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-427-safe.txt", &[]);
}

#[test]
fn cwe_434_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-434-vulnerable.txt",
        &["CWE-434"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-434-safe.txt", &[]);
}

#[test]
fn cwe_454_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-454-vulnerable.txt",
        &["CWE-454"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-454-safe.txt", &[]);
}

#[test]
fn cwe_455_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-455-vulnerable.txt",
        &["CWE-455"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-455-safe.txt", &[]);
}

#[test]
fn cwe_459_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-459-vulnerable.txt",
        &["CWE-459"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-459-safe.txt", &[]);
}

#[test]
fn cwe_472_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-472-vulnerable.txt",
        &["CWE-472"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-472-safe.txt", &[]);
}

#[test]
fn cwe_488_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-488-vulnerable.txt",
        &["CWE-488"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-488-safe.txt", &[]);
}

#[test]
fn cwe_494_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-494-vulnerable.txt",
        &["CWE-494"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-494-safe.txt", &[]);
}

#[test]
fn cwe_497_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-497-vulnerable.txt",
        &["CWE-497"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-497-safe.txt", &[]);
}

#[test]
fn cwe_501_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-501-vulnerable.txt",
        &["CWE-501"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-501-safe.txt", &[]);
}

#[test]
fn cwe_502_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-502-vulnerable.txt",
        &["CWE-502"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-502-safe.txt", &[]);
}

#[test]
fn cwe_515_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-515-vulnerable.txt",
        &["CWE-515"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-515-safe.txt", &[]);
}

#[test]
fn cwe_521_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-521-vulnerable.txt",
        &["CWE-521"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-521-safe.txt", &[]);
}

#[test]
fn cwe_523_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-523-vulnerable.txt",
        &["CWE-523"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-523-safe.txt", &[]);
}

#[test]
fn cwe_524_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-524-vulnerable.txt",
        &["CWE-524"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-524-safe.txt", &[]);
}

#[test]
fn cwe_547_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-547-vulnerable.txt",
        &["CWE-547"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-547-safe.txt", &[]);
}

#[test]
fn cwe_538_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-538-vulnerable.txt",
        &["CWE-538"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-538-safe.txt", &[]);
}

#[test]
fn cwe_544_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-544-vulnerable.txt",
        &["CWE-544"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-544-safe.txt", &[]);
}

#[test]
fn cwe_549_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-549-vulnerable.txt",
        &["CWE-549"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-549-safe.txt", &[]);
}

#[test]
fn cwe_551_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-551-vulnerable.txt",
        &["CWE-551"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-551-safe.txt", &[]);
}

#[test]
fn cwe_552_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-552-vulnerable.txt",
        &["CWE-552"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-552-safe.txt", &[]);
}

#[test]
fn cwe_565_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-565-vulnerable.txt",
        &["CWE-565"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-565-safe.txt", &[]);
}

#[test]
fn cwe_601_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-601-vulnerable.txt",
        &["CWE-601"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-601-safe.txt", &[]);
}

#[test]
fn cwe_603_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-603-vulnerable.txt",
        &["CWE-603"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-603-safe.txt", &[]);
}

#[test]
fn cwe_605_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-605-vulnerable.txt",
        &["CWE-605"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-605-safe.txt", &[]);
}

#[test]
fn cwe_611_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-611-vulnerable.txt",
        &["CWE-611"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-611-safe.txt", &[]);
}

#[test]
fn cwe_613_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-613-vulnerable.txt",
        &["CWE-613"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-613-safe.txt", &[]);
}

#[test]
fn cwe_618_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-618-vulnerable.txt",
        &["CWE-618"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-618-safe.txt", &[]);
}

#[test]
fn cwe_619_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-619-vulnerable.txt",
        &["CWE-619"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-619-safe.txt", &[]);
}

#[test]
fn cwe_620_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-620-vulnerable.txt",
        &["CWE-620"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-620-safe.txt", &[]);
}

#[test]
fn cwe_639_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-639-vulnerable.txt",
        &["CWE-639"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-639-safe.txt", &[]);
}

#[test]
fn cwe_640_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-640-vulnerable.txt",
        &["CWE-640"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-640-safe.txt", &[]);
}

#[test]
fn cwe_645_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-645-vulnerable.txt",
        &["CWE-645"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-645-safe.txt", &[]);
}

#[test]
fn cwe_648_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-648-vulnerable.txt",
        &["CWE-648"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-648-safe.txt", &[]);
}

#[test]
fn cwe_649_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-649-vulnerable.txt",
        &["CWE-649"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-649-safe.txt", &[]);
}

#[test]
fn cwe_653_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-653-vulnerable.txt",
        &["CWE-653"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-653-safe.txt", &[]);
}

#[test]
fn cwe_654_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-654-vulnerable.txt",
        &["CWE-654"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-654-safe.txt", &[]);
}

#[test]
fn cwe_656_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-656-vulnerable.txt",
        &["CWE-656"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-656-safe.txt", &[]);
}

#[test]
fn cwe_708_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-708-vulnerable.txt",
        &["CWE-708"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-708-safe.txt", &[]);
}

#[test]
fn cwe_756_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-756-vulnerable.txt",
        &["CWE-756"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-756-safe.txt", &[]);
}

#[test]
fn cwe_765_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-765-vulnerable.txt",
        &["CWE-765"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-765-safe.txt", &[]);
}

#[test]
fn cwe_778_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-778-vulnerable.txt",
        &["CWE-778"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-778-safe.txt", &[]);
}

#[test]
fn cwe_783_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-783-vulnerable.txt",
        &["CWE-783"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-783-safe.txt", &[]);
}

#[test]
fn cwe_798_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-798-vulnerable.txt",
        &["CWE-798"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-798-safe.txt", &[]);
}

#[test]
fn cwe_820_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-820-vulnerable.txt",
        &["CWE-820"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-820-safe.txt", &[]);
}

#[test]
fn cwe_821_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-821-vulnerable.txt",
        &["CWE-821"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-821-safe.txt", &[]);
}

#[test]
fn cwe_826_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-826-vulnerable.txt",
        &["CWE-826"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-826-safe.txt", &[]);
}

#[test]
fn cwe_829_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-829-vulnerable.txt",
        &["CWE-829"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-829-safe.txt", &[]);
}

#[test]
fn cwe_836_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-836-vulnerable.txt",
        &["CWE-836"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-836-safe.txt", &[]);
}

#[test]
fn cwe_838_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-838-vulnerable.txt",
        &["CWE-838"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-838-safe.txt", &[]);
}

#[test]
fn cwe_841_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-841-vulnerable.txt",
        &["CWE-841"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-841-safe.txt", &[]);
}

#[test]
fn cwe_842_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-842-vulnerable.txt",
        &["CWE-842"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-842-safe.txt", &[]);
}

#[test]
fn cwe_909_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-909-vulnerable.txt",
        &["CWE-909"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-909-safe.txt", &[]);
}

#[test]
fn cwe_915_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-915-vulnerable.txt",
        &["CWE-915"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-915-safe.txt", &[]);
}

#[test]
fn cwe_916_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-916-vulnerable.txt",
        &["CWE-916"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-916-safe.txt", &[]);
}

#[test]
fn cwe_917_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-917-vulnerable.txt",
        &["CWE-917"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-917-safe.txt", &[]);
}

#[test]
fn cwe_918_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-918-vulnerable.txt",
        &["CWE-918"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-918-safe.txt", &[]);
}

#[test]
fn cwe_921_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-921-vulnerable.txt",
        &["CWE-921"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-921-safe.txt", &[]);
}

#[test]
fn cwe_924_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-924-vulnerable.txt",
        &["CWE-924"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-924-safe.txt", &[]);
}

#[test]
fn cwe_924_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-924-vulnerable.txt",
        &["CWE-924"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-924-safe.txt", &[]);
}

#[test]
fn cwe_940_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-940-vulnerable.txt",
        &["CWE-940"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-940-safe.txt", &[]);
}

#[test]
fn cwe_940_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-940-vulnerable.txt",
        &["CWE-940"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-940-safe.txt", &[]);
}

#[test]
fn cwe_941_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-941-vulnerable.txt",
        &["CWE-941"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-941-safe.txt", &[]);
}

#[test]
fn cwe_941_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-941-vulnerable.txt",
        &["CWE-941"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-941-safe.txt", &[]);
}

#[test]
fn cwe_1051_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1051-vulnerable.txt",
        &["CWE-1051"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1051-safe.txt", &[]);
}

#[test]
fn cwe_1051_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1051-vulnerable.txt",
        &["CWE-1051"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1051-safe.txt", &[]);
}

#[test]
fn cwe_1052_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1052-vulnerable.txt",
        &["CWE-1052"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1052-safe.txt", &[]);
}

#[test]
fn cwe_1052_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1052-vulnerable.txt",
        &["CWE-1052"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1052-safe.txt", &[]);
}

#[test]
fn cwe_1067_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1067-vulnerable.txt",
        &["CWE-1067"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1067-safe.txt", &[]);
}

#[test]
fn cwe_1067_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1067-vulnerable.txt",
        &["CWE-1067"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1067-safe.txt", &[]);
}

#[test]
fn cwe_1173_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1173-vulnerable.txt",
        &["CWE-1173"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1173-safe.txt", &[]);
}

#[test]
fn cwe_1173_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1173-vulnerable.txt",
        &["CWE-1173"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1173-safe.txt", &[]);
}

#[test]
fn cwe_1125_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1125-vulnerable.txt",
        &["CWE-1125"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1125-safe.txt", &[]);
}

#[test]
fn cwe_1125_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1125-vulnerable.txt",
        &["CWE-1125"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1125-safe.txt", &[]);
}

#[test]
fn cwe_1204_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1204-vulnerable.txt",
        &["CWE-1204"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1204-safe.txt", &[]);
}

#[test]
fn cwe_1204_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1204-vulnerable.txt",
        &["CWE-1204"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1204-safe.txt", &[]);
}

#[test]
fn cwe_1220_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1220-vulnerable.txt",
        &["CWE-1220"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1220-safe.txt", &[]);
}

#[test]
fn cwe_1220_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1220-vulnerable.txt",
        &["CWE-1220"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1220-safe.txt", &[]);
}

#[test]
fn cwe_1230_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1230-vulnerable.txt",
        &["CWE-1230"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1230-safe.txt", &[]);
}

#[test]
fn cwe_1230_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1230-vulnerable.txt",
        &["CWE-1230"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1230-safe.txt", &[]);
}

#[test]
fn cwe_1236_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1236-vulnerable.txt",
        &["CWE-1236"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1236-safe.txt", &[]);
}

#[test]
fn cwe_1236_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1236-vulnerable.txt",
        &["CWE-1236"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1236-safe.txt", &[]);
}

#[test]
fn cwe_1240_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1240-vulnerable.txt",
        &["CWE-1240"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1240-safe.txt", &[]);
}

#[test]
fn cwe_1240_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1240-vulnerable.txt",
        &["CWE-1240"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1240-safe.txt", &[]);
}

#[test]
fn cwe_1265_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1265-vulnerable.txt",
        &["CWE-1265"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1265-safe.txt", &[]);
}

#[test]
fn cwe_1265_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1265-vulnerable.txt",
        &["CWE-1265"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1265-safe.txt", &[]);
}

#[test]
fn cwe_1286_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1286-vulnerable.txt",
        &["CWE-1286"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1286-safe.txt", &[]);
}

#[test]
fn cwe_1286_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1286-vulnerable.txt",
        &["CWE-1286"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1286-safe.txt", &[]);
}

#[test]
fn cwe_1289_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1289-vulnerable.txt",
        &["CWE-1289"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1289-safe.txt", &[]);
}

#[test]
fn cwe_1289_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1289-vulnerable.txt",
        &["CWE-1289"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1289-safe.txt", &[]);
}

#[test]
fn cwe_1322_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1322-vulnerable.txt",
        &["CWE-1322"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1322-safe.txt", &[]);
}

#[test]
fn cwe_1322_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1322-vulnerable.txt",
        &["CWE-1322"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1322-safe.txt", &[]);
}

#[test]
fn cwe_1327_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1327-vulnerable.txt",
        &["CWE-1327"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1327-safe.txt", &[]);
}

#[test]
fn cwe_1327_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1327-vulnerable.txt",
        &["CWE-1327"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1327-safe.txt", &[]);
}

#[test]
fn cwe_1333_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1333-vulnerable.txt",
        &["CWE-1333"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1333-safe.txt", &[]);
}

#[test]
fn cwe_1333_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1333-vulnerable.txt",
        &["CWE-1333"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1333-safe.txt", &[]);
}

#[test]
fn cwe_1389_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1389-vulnerable.txt",
        &["CWE-1389"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1389-safe.txt", &[]);
}

#[test]
fn cwe_1389_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1389-vulnerable.txt",
        &["CWE-1389"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1389-safe.txt", &[]);
}

#[test]
fn cwe_1392_framework_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/frameworks/CWE-1392-vulnerable.txt",
        &["CWE-1392"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/frameworks/CWE-1392-safe.txt", &[]);
}

#[test]
fn cwe_1392_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-1392-vulnerable.txt",
        &["CWE-1392"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-1392-safe.txt", &[]);
}

#[test]
fn cwe_807_stdlib_fixture_pair() {
    helpers::assert_fixture_rules(
        "tests/fixtures/go/stdlib/CWE-807-vulnerable.txt",
        &["CWE-807"],
    );
    helpers::assert_fixture_rules("tests/fixtures/go/stdlib/CWE-807-safe.txt", &[]);
}
