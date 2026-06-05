//! Go CWE detector regression tests.
//!
//! Each `CWE-N` rule has a vulnerable fixture (must fire) and a safe fixture
//! (must not fire), in both the `frameworks` and `stdlib` directories. The
//! list below is the single source of truth — derived from the directory
//! listing of `tests/fixtures/go/{frameworks,stdlib}/CWE-*-vulnerable.txt`.
//!
//! To add a new CWE fixture: drop the `.txt` files into both directories, then
//! add the CWE number to `CASES` below.

#[path = "helpers/mod.rs"]
mod helpers;

const CASES: &[(u32, &str)] = &[
    (15, "CWE-15"),
    (22, "CWE-22"),
    (41, "CWE-41"),
    (59, "CWE-59"),
    (76, "CWE-76"),
    (78, "CWE-78"),
    (79, "CWE-79"),
    (89, "CWE-89"),
    (90, "CWE-90"),
    (91, "CWE-91"),
    (93, "CWE-93"),
    (112, "CWE-112"),
    (140, "CWE-140"),
    (178, "CWE-178"),
    (179, "CWE-179"),
    (182, "CWE-182"),
    (184, "CWE-184"),
    (186, "CWE-186"),
    (201, "CWE-201"),
    (204, "CWE-204"),
    (208, "CWE-208"),
    (209, "CWE-209"),
    (212, "CWE-212"),
    (213, "CWE-213"),
    (214, "CWE-214"),
    (215, "CWE-215"),
    (250, "CWE-250"),
    (252, "CWE-252"),
    (256, "CWE-256"),
    (257, "CWE-257"),
    (260, "CWE-260"),
    (261, "CWE-261"),
    (262, "CWE-262"),
    (263, "CWE-263"),
    (266, "CWE-266"),
    (267, "CWE-267"),
    (268, "CWE-268"),
    (270, "CWE-270"),
    (272, "CWE-272"),
    (273, "CWE-273"),
    (274, "CWE-274"),
    (276, "CWE-276"),
    (277, "CWE-277"),
    (278, "CWE-278"),
    (279, "CWE-279"),
    (280, "CWE-280"),
    (281, "CWE-281"),
    (283, "CWE-283"),
    (289, "CWE-289"),
    (290, "CWE-290"),
    (294, "CWE-294"),
    (301, "CWE-301"),
    (303, "CWE-303"),
    (305, "CWE-305"),
    (306, "CWE-306"),
    (307, "CWE-307"),
    (308, "CWE-308"),
    (309, "CWE-309"),
    (312, "CWE-312"),
    (319, "CWE-319"),
    (322, "CWE-322"),
    (323, "CWE-323"),
    (324, "CWE-324"),
    (325, "CWE-325"),
    (328, "CWE-328"),
    (331, "CWE-331"),
    (334, "CWE-334"),
    (335, "CWE-335"),
    (338, "CWE-338"),
    (341, "CWE-341"),
    (342, "CWE-342"),
    (343, "CWE-343"),
    (344, "CWE-344"),
    (346, "CWE-346"),
    (347, "CWE-347"),
    (349, "CWE-349"),
    (353, "CWE-353"),
    (356, "CWE-356"),
    (358, "CWE-358"),
    (359, "CWE-359"),
    (360, "CWE-360"),
    (366, "CWE-366"),
    (367, "CWE-367"),
    (368, "CWE-368"),
    (378, "CWE-378"),
    (379, "CWE-379"),
    (385, "CWE-385"),
    (393, "CWE-393"),
    (403, "CWE-403"),
    (408, "CWE-408"),
    (412, "CWE-412"),
    (420, "CWE-420"),
    (421, "CWE-421"),
    (425, "CWE-425"),
    (426, "CWE-426"),
    (427, "CWE-427"),
    (434, "CWE-434"),
    (454, "CWE-454"),
    (455, "CWE-455"),
    (459, "CWE-459"),
    (472, "CWE-472"),
    (488, "CWE-488"),
    (494, "CWE-494"),
    (497, "CWE-497"),
    (501, "CWE-501"),
    (502, "CWE-502"),
    (515, "CWE-515"),
    (521, "CWE-521"),
    (523, "CWE-523"),
    (524, "CWE-524"),
    (538, "CWE-538"),
    (544, "CWE-544"),
    (547, "CWE-547"),
    (549, "CWE-549"),
    (551, "CWE-551"),
    (552, "CWE-552"),
    (565, "CWE-565"),
    (601, "CWE-601"),
    (603, "CWE-603"),
    (605, "CWE-605"),
    (611, "CWE-611"),
    (613, "CWE-613"),
    (618, "CWE-618"),
    (619, "CWE-619"),
    (620, "CWE-620"),
    (639, "CWE-639"),
    (640, "CWE-640"),
    (645, "CWE-645"),
    (648, "CWE-648"),
    (649, "CWE-649"),
    (653, "CWE-653"),
    (654, "CWE-654"),
    (656, "CWE-656"),
    (708, "CWE-708"),
    (756, "CWE-756"),
    (765, "CWE-765"),
    (778, "CWE-778"),
    (783, "CWE-783"),
    (798, "CWE-798"),
    (807, "CWE-807"),
    (820, "CWE-820"),
    (821, "CWE-821"),
    (826, "CWE-826"),
    (829, "CWE-829"),
    (836, "CWE-836"),
    (838, "CWE-838"),
    (841, "CWE-841"),
    (842, "CWE-842"),
    (909, "CWE-909"),
    (915, "CWE-915"),
    (916, "CWE-916"),
    (917, "CWE-917"),
    (918, "CWE-918"),
    (921, "CWE-921"),
    (924, "CWE-924"),
    (940, "CWE-940"),
    (941, "CWE-941"),
    (1051, "CWE-1051"),
    (1052, "CWE-1052"),
    (1067, "CWE-1067"),
    (1125, "CWE-1125"),
    (1173, "CWE-1173"),
    (1204, "CWE-1204"),
    (1220, "CWE-1220"),
    (1230, "CWE-1230"),
    (1236, "CWE-1236"),
    (1240, "CWE-1240"),
    (1265, "CWE-1265"),
    (1286, "CWE-1286"),
    (1289, "CWE-1289"),
    (1322, "CWE-1322"),
    (1327, "CWE-1327"),
    (1333, "CWE-1333"),
    (1389, "CWE-1389"),
    (1392, "CWE-1392"),
];

#[test]
fn go_cwe_fixtures_fire_vulnerable_and_silence_safe() {
    let mut failures: Vec<String> = Vec::new();
    for (_num, cwe) in CASES {
        for suite in ["frameworks", "stdlib"] {
            let base = format!("tests/fixtures/go/{suite}/{cwe}");
            let vulnerable = format!("{base}-vulnerable.txt");
            let safe = format!("{base}-safe.txt");
            if let Err(e) = std::panic::catch_unwind(|| {
                helpers::assert_fixture_rules(&vulnerable, &[cwe]);
                helpers::assert_fixture_rules(&safe, &[]);
            }) {
                failures.push(format!("{suite}/{cwe}: {e:?}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} CWE fixtures failed: {failures:#?}",
        failures.len(),
        CASES.len() * 2,
    );
}

#[test]
fn go_cwe_fixtures_have_unique_cwe_numbers() {
    let mut seen = std::collections::HashSet::new();
    for (num, cwe) in CASES {
        assert!(seen.insert(*num), "duplicate CWE number in CASES: {num}");
        assert_eq!(&format!("CWE-{num}"), cwe, "CASES entry mismatch: {num} != {cwe}");
    }
}
