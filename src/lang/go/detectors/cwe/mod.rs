//! Bundled Go CWE heuristics.

pub mod facts;

pub mod common;
mod detector_group_a;
mod detector_group_b;
mod detector_group_c;
mod metadata;

use self::detector_group_a::*;
use self::detector_group_b::*;
use self::detector_group_c::*;
use self::facts::build_go_unit_facts;

/// Define a per-rule Go CWE detector.
macro_rules! define_detector {
    ($name:ident, $rule_id:literal, $detector_fn:ident, $meta:ident) => {
        pub struct $name;

        impl crate::rules::Rule for $name {
            fn metadata(&self) -> crate::rules::RuleMetadata {
                self::metadata::$meta
            }
        }

        impl crate::core::Detector for $name {
            fn language(&self) -> crate::core::LanguageId {
                crate::core::LanguageId::Go
            }

            fn rule_ids(&self) -> &'static [&'static str] {
                &[$rule_id]
            }

            fn run(
                &self,
                ctx: &crate::core::ScanContext,
                unit: &crate::core::ParsedUnit,
                out: &mut Vec<crate::rules::Finding>,
            ) {
                if ctx.allows($rule_id) {
                    $detector_fn(unit, &build_go_unit_facts(unit), out);
                }
            }
        }
    };
}

define_detector!(Cwe15, "CWE-15", detect_cwe_15, META_CWE_15);
define_detector!(Cwe22, "CWE-22", detect_cwe_22, META_CWE_22);
define_detector!(Cwe41, "CWE-41", detect_cwe_41, META_CWE_41);
define_detector!(Cwe59, "CWE-59", detect_cwe_59, META_CWE_59);
define_detector!(Cwe76, "CWE-76", detect_cwe_76, META_CWE_76);
define_detector!(Cwe78, "CWE-78", detect_cwe_78, META_CWE_78);
define_detector!(Cwe79, "CWE-79", detect_cwe_79, META_CWE_79);
define_detector!(Cwe89, "CWE-89", detect_cwe_89, META_CWE_89);
define_detector!(Cwe90, "CWE-90", detect_cwe_90, META_CWE_90);
define_detector!(Cwe91, "CWE-91", detect_cwe_91, META_CWE_91);
define_detector!(Cwe93, "CWE-93", detect_cwe_93, META_CWE_93);
define_detector!(Cwe112, "CWE-112", detect_cwe_112, META_CWE_112);
define_detector!(Cwe140, "CWE-140", detect_cwe_140, META_CWE_140);
define_detector!(Cwe178, "CWE-178", detect_cwe_178, META_CWE_178);
define_detector!(Cwe179, "CWE-179", detect_cwe_179, META_CWE_179);
define_detector!(Cwe182, "CWE-182", detect_cwe_182, META_CWE_182);
define_detector!(Cwe184, "CWE-184", detect_cwe_184, META_CWE_184);
define_detector!(Cwe186, "CWE-186", detect_cwe_186, META_CWE_186);
define_detector!(Cwe201, "CWE-201", detect_cwe_201, META_CWE_201);
define_detector!(Cwe204, "CWE-204", detect_cwe_204, META_CWE_204);
define_detector!(Cwe208, "CWE-208", detect_cwe_208, META_CWE_208);
define_detector!(Cwe209, "CWE-209", detect_cwe_209, META_CWE_209);
define_detector!(Cwe212, "CWE-212", detect_cwe_212, META_CWE_212);
define_detector!(Cwe213, "CWE-213", detect_cwe_213, META_CWE_213);
define_detector!(Cwe214, "CWE-214", detect_cwe_214, META_CWE_214);
define_detector!(Cwe215, "CWE-215", detect_cwe_215, META_CWE_215);
define_detector!(Cwe250, "CWE-250", detect_cwe_250, META_CWE_250);
define_detector!(Cwe252, "CWE-252", detect_cwe_252, META_CWE_252);
define_detector!(Cwe256, "CWE-256", detect_cwe_256, META_CWE_256);
define_detector!(Cwe257, "CWE-257", detect_cwe_257, META_CWE_257);
define_detector!(Cwe260, "CWE-260", detect_cwe_260, META_CWE_260);
define_detector!(Cwe261, "CWE-261", detect_cwe_261, META_CWE_261);
define_detector!(Cwe262, "CWE-262", detect_cwe_262, META_CWE_262);
define_detector!(Cwe263, "CWE-263", detect_cwe_263, META_CWE_263);
define_detector!(Cwe266, "CWE-266", detect_cwe_266, META_CWE_266);
define_detector!(Cwe267, "CWE-267", detect_cwe_267, META_CWE_267);
define_detector!(Cwe268, "CWE-268", detect_cwe_268, META_CWE_268);
define_detector!(Cwe270, "CWE-270", detect_cwe_270, META_CWE_270);
define_detector!(Cwe272, "CWE-272", detect_cwe_272, META_CWE_272);
define_detector!(Cwe273, "CWE-273", detect_cwe_273, META_CWE_273);
define_detector!(Cwe274, "CWE-274", detect_cwe_274, META_CWE_274);
define_detector!(Cwe276, "CWE-276", detect_cwe_276, META_CWE_276);
define_detector!(Cwe277, "CWE-277", detect_cwe_277, META_CWE_277);
define_detector!(Cwe278, "CWE-278", detect_cwe_278, META_CWE_278);
define_detector!(Cwe279, "CWE-279", detect_cwe_279, META_CWE_279);
define_detector!(Cwe280, "CWE-280", detect_cwe_280, META_CWE_280);
define_detector!(Cwe281, "CWE-281", detect_cwe_281, META_CWE_281);
define_detector!(Cwe283, "CWE-283", detect_cwe_283, META_CWE_283);
define_detector!(Cwe289, "CWE-289", detect_cwe_289, META_CWE_289);
define_detector!(Cwe290, "CWE-290", detect_cwe_290, META_CWE_290);
define_detector!(Cwe294, "CWE-294", detect_cwe_294, META_CWE_294);
define_detector!(Cwe301, "CWE-301", detect_cwe_301, META_CWE_301);
define_detector!(Cwe303, "CWE-303", detect_cwe_303, META_CWE_303);
define_detector!(Cwe305, "CWE-305", detect_cwe_305, META_CWE_305);
define_detector!(Cwe306, "CWE-306", detect_cwe_306, META_CWE_306);
define_detector!(Cwe307, "CWE-307", detect_cwe_307, META_CWE_307);
define_detector!(Cwe308, "CWE-308", detect_cwe_308, META_CWE_308);
define_detector!(Cwe309, "CWE-309", detect_cwe_309, META_CWE_309);
define_detector!(Cwe312, "CWE-312", detect_cwe_312, META_CWE_312);
define_detector!(Cwe319, "CWE-319", detect_cwe_319, META_CWE_319);
define_detector!(Cwe322, "CWE-322", detect_cwe_322, META_CWE_322);
define_detector!(Cwe323, "CWE-323", detect_cwe_323, META_CWE_323);
define_detector!(Cwe324, "CWE-324", detect_cwe_324, META_CWE_324);
define_detector!(Cwe325, "CWE-325", detect_cwe_325, META_CWE_325);
define_detector!(Cwe328, "CWE-328", detect_cwe_328, META_CWE_328);
define_detector!(Cwe331, "CWE-331", detect_cwe_331, META_CWE_331);
define_detector!(Cwe334, "CWE-334", detect_cwe_334, META_CWE_334);
define_detector!(Cwe335, "CWE-335", detect_cwe_335, META_CWE_335);
define_detector!(Cwe338, "CWE-338", detect_cwe_338, META_CWE_338);
define_detector!(Cwe341, "CWE-341", detect_cwe_341, META_CWE_341);
define_detector!(Cwe342, "CWE-342", detect_cwe_342, META_CWE_342);
define_detector!(Cwe343, "CWE-343", detect_cwe_343, META_CWE_343);
define_detector!(Cwe344, "CWE-344", detect_cwe_344, META_CWE_344);
define_detector!(Cwe346, "CWE-346", detect_cwe_346, META_CWE_346);
define_detector!(Cwe347, "CWE-347", detect_cwe_347, META_CWE_347);
define_detector!(Cwe349, "CWE-349", detect_cwe_349, META_CWE_349);
define_detector!(Cwe353, "CWE-353", detect_cwe_353, META_CWE_353);
define_detector!(Cwe356, "CWE-356", detect_cwe_356, META_CWE_356);
define_detector!(Cwe358, "CWE-358", detect_cwe_358, META_CWE_358);
define_detector!(Cwe359, "CWE-359", detect_cwe_359, META_CWE_359);
define_detector!(Cwe360, "CWE-360", detect_cwe_360, META_CWE_360);
define_detector!(Cwe366, "CWE-366", detect_cwe_366, META_CWE_366);
define_detector!(Cwe367, "CWE-367", detect_cwe_367, META_CWE_367);
define_detector!(Cwe368, "CWE-368", detect_cwe_368, META_CWE_368);
define_detector!(Cwe378, "CWE-378", detect_cwe_378, META_CWE_378);
define_detector!(Cwe379, "CWE-379", detect_cwe_379, META_CWE_379);
define_detector!(Cwe385, "CWE-385", detect_cwe_385, META_CWE_385);
define_detector!(Cwe393, "CWE-393", detect_cwe_393, META_CWE_393);
define_detector!(Cwe403, "CWE-403", detect_cwe_403, META_CWE_403);
define_detector!(Cwe408, "CWE-408", detect_cwe_408, META_CWE_408);
define_detector!(Cwe412, "CWE-412", detect_cwe_412, META_CWE_412);
define_detector!(Cwe420, "CWE-420", detect_cwe_420, META_CWE_420);
define_detector!(Cwe421, "CWE-421", detect_cwe_421, META_CWE_421);
define_detector!(Cwe425, "CWE-425", detect_cwe_425, META_CWE_425);
define_detector!(Cwe426, "CWE-426", detect_cwe_426, META_CWE_426);
define_detector!(Cwe427, "CWE-427", detect_cwe_427, META_CWE_427);
define_detector!(Cwe434, "CWE-434", detect_cwe_434, META_CWE_434);
define_detector!(Cwe454, "CWE-454", detect_cwe_454, META_CWE_454);
define_detector!(Cwe455, "CWE-455", detect_cwe_455, META_CWE_455);
define_detector!(Cwe459, "CWE-459", detect_cwe_459, META_CWE_459);
define_detector!(Cwe472, "CWE-472", detect_cwe_472, META_CWE_472);
define_detector!(Cwe488, "CWE-488", detect_cwe_488, META_CWE_488);
define_detector!(Cwe494, "CWE-494", detect_cwe_494, META_CWE_494);
define_detector!(Cwe497, "CWE-497", detect_cwe_497, META_CWE_497);
define_detector!(Cwe501, "CWE-501", detect_cwe_501, META_CWE_501);
define_detector!(Cwe502, "CWE-502", detect_cwe_502, META_CWE_502);
define_detector!(Cwe515, "CWE-515", detect_cwe_515, META_CWE_515);
define_detector!(Cwe521, "CWE-521", detect_cwe_521, META_CWE_521);
define_detector!(Cwe523, "CWE-523", detect_cwe_523, META_CWE_523);
define_detector!(Cwe524, "CWE-524", detect_cwe_524, META_CWE_524);
define_detector!(Cwe538, "CWE-538", detect_cwe_538, META_CWE_538);
define_detector!(Cwe544, "CWE-544", detect_cwe_544, META_CWE_544);
define_detector!(Cwe547, "CWE-547", detect_cwe_547, META_CWE_547);
define_detector!(Cwe549, "CWE-549", detect_cwe_549, META_CWE_549);
define_detector!(Cwe551, "CWE-551", detect_cwe_551, META_CWE_551);
define_detector!(Cwe552, "CWE-552", detect_cwe_552, META_CWE_552);
define_detector!(Cwe565, "CWE-565", detect_cwe_565, META_CWE_565);
define_detector!(Cwe601, "CWE-601", detect_cwe_601, META_CWE_601);
define_detector!(Cwe603, "CWE-603", detect_cwe_603, META_CWE_603);
define_detector!(Cwe605, "CWE-605", detect_cwe_605, META_CWE_605);
define_detector!(Cwe611, "CWE-611", detect_cwe_611, META_CWE_611);
define_detector!(Cwe613, "CWE-613", detect_cwe_613, META_CWE_613);
define_detector!(Cwe618, "CWE-618", detect_cwe_618, META_CWE_618);
define_detector!(Cwe619, "CWE-619", detect_cwe_619, META_CWE_619);
define_detector!(Cwe620, "CWE-620", detect_cwe_620, META_CWE_620);
define_detector!(Cwe639, "CWE-639", detect_cwe_639, META_CWE_639);
define_detector!(Cwe640, "CWE-640", detect_cwe_640, META_CWE_640);
define_detector!(Cwe645, "CWE-645", detect_cwe_645, META_CWE_645);
define_detector!(Cwe648, "CWE-648", detect_cwe_648, META_CWE_648);
define_detector!(Cwe649, "CWE-649", detect_cwe_649, META_CWE_649);
define_detector!(Cwe653, "CWE-653", detect_cwe_653, META_CWE_653);
define_detector!(Cwe654, "CWE-654", detect_cwe_654, META_CWE_654);
define_detector!(Cwe656, "CWE-656", detect_cwe_656, META_CWE_656);
define_detector!(Cwe708, "CWE-708", detect_cwe_708, META_CWE_708);
define_detector!(Cwe756, "CWE-756", detect_cwe_756, META_CWE_756);
define_detector!(Cwe765, "CWE-765", detect_cwe_765, META_CWE_765);
define_detector!(Cwe778, "CWE-778", detect_cwe_778, META_CWE_778);
define_detector!(Cwe783, "CWE-783", detect_cwe_783, META_CWE_783);
define_detector!(Cwe798, "CWE-798", detect_cwe_798, META_CWE_798);
define_detector!(Cwe807, "CWE-807", detect_cwe_807, META_CWE_807);
define_detector!(Cwe820, "CWE-820", detect_cwe_820, META_CWE_820);
define_detector!(Cwe821, "CWE-821", detect_cwe_821, META_CWE_821);
define_detector!(Cwe826, "CWE-826", detect_cwe_826, META_CWE_826);
define_detector!(Cwe829, "CWE-829", detect_cwe_829, META_CWE_829);
define_detector!(Cwe836, "CWE-836", detect_cwe_836, META_CWE_836);
define_detector!(Cwe838, "CWE-838", detect_cwe_838, META_CWE_838);
define_detector!(Cwe841, "CWE-841", detect_cwe_841, META_CWE_841);
define_detector!(Cwe842, "CWE-842", detect_cwe_842, META_CWE_842);
define_detector!(Cwe909, "CWE-909", detect_cwe_909, META_CWE_909);
define_detector!(Cwe915, "CWE-915", detect_cwe_915, META_CWE_915);
define_detector!(Cwe916, "CWE-916", detect_cwe_916, META_CWE_916);
define_detector!(Cwe917, "CWE-917", detect_cwe_917, META_CWE_917);
define_detector!(Cwe918, "CWE-918", detect_cwe_918, META_CWE_918);
define_detector!(Cwe921, "CWE-921", detect_cwe_921, META_CWE_921);
define_detector!(Cwe924, "CWE-924", detect_cwe_924, META_CWE_924);
define_detector!(Cwe940, "CWE-940", detect_cwe_940, META_CWE_940);
define_detector!(Cwe941, "CWE-941", detect_cwe_941, META_CWE_941);
define_detector!(Cwe1051, "CWE-1051", detect_cwe_1051, META_CWE_1051);
define_detector!(Cwe1052, "CWE-1052", detect_cwe_1052, META_CWE_1052);
define_detector!(Cwe1067, "CWE-1067", detect_cwe_1067, META_CWE_1067);
define_detector!(Cwe1125, "CWE-1125", detect_cwe_1125, META_CWE_1125);
define_detector!(Cwe1173, "CWE-1173", detect_cwe_1173, META_CWE_1173);
define_detector!(Cwe1204, "CWE-1204", detect_cwe_1204, META_CWE_1204);
define_detector!(Cwe1220, "CWE-1220", detect_cwe_1220, META_CWE_1220);
define_detector!(Cwe1230, "CWE-1230", detect_cwe_1230, META_CWE_1230);
define_detector!(Cwe1236, "CWE-1236", detect_cwe_1236, META_CWE_1236);
define_detector!(Cwe1240, "CWE-1240", detect_cwe_1240, META_CWE_1240);
define_detector!(Cwe1265, "CWE-1265", detect_cwe_1265, META_CWE_1265);
define_detector!(Cwe1286, "CWE-1286", detect_cwe_1286, META_CWE_1286);
define_detector!(Cwe1289, "CWE-1289", detect_cwe_1289, META_CWE_1289);
define_detector!(Cwe1322, "CWE-1322", detect_cwe_1322, META_CWE_1322);
define_detector!(Cwe1327, "CWE-1327", detect_cwe_1327, META_CWE_1327);
define_detector!(Cwe1333, "CWE-1333", detect_cwe_1333, META_CWE_1333);
define_detector!(Cwe1389, "CWE-1389", detect_cwe_1389, META_CWE_1389);
define_detector!(Cwe1392, "CWE-1392", detect_cwe_1392, META_CWE_1392);
