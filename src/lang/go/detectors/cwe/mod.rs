//! Bundled Go CWE heuristics.

pub mod facts;

mod common;
mod detector_group_a;
mod detector_group_b;
mod detector_group_c;
mod metadata;

use crate::core::{Detector, LanguageId, ParsedUnit, ScanContext};
use crate::rules::{Finding, Rule, RuleMetadata};

use self::detector_group_a::*;
use self::detector_group_b::*;
use self::detector_group_c::*;
use self::facts::build_go_unit_facts;
use self::metadata::{GO_CWE_RULE_IDS, META_CWE_15};

pub struct GoCweScan;

type DetectorFn = fn(&ParsedUnit, &facts::GoUnitFacts, &mut Vec<Finding>);

const DETECTORS: &[(&str, DetectorFn)] = &[
    ("CWE-15", detect_cwe_15),
    ("CWE-22", detect_cwe_22),
    ("CWE-41", detect_cwe_41),
    ("CWE-59", detect_cwe_59),
    ("CWE-76", detect_cwe_76),
    ("CWE-78", detect_cwe_78),
    ("CWE-79", detect_cwe_79),
    ("CWE-89", detect_cwe_89),
    ("CWE-90", detect_cwe_90),
    ("CWE-91", detect_cwe_91),
    ("CWE-93", detect_cwe_93),
    ("CWE-112", detect_cwe_112),
    ("CWE-140", detect_cwe_140),
    ("CWE-178", detect_cwe_178),
    ("CWE-179", detect_cwe_179),
    ("CWE-182", detect_cwe_182),
    ("CWE-184", detect_cwe_184),
    ("CWE-186", detect_cwe_186),
    ("CWE-201", detect_cwe_201),
    ("CWE-204", detect_cwe_204),
    ("CWE-208", detect_cwe_208),
    ("CWE-209", detect_cwe_209),
    ("CWE-212", detect_cwe_212),
    ("CWE-213", detect_cwe_213),
    ("CWE-214", detect_cwe_214),
    ("CWE-215", detect_cwe_215),
    ("CWE-250", detect_cwe_250),
    ("CWE-252", detect_cwe_252),
    ("CWE-256", detect_cwe_256),
    ("CWE-257", detect_cwe_257),
    ("CWE-260", detect_cwe_260),
    ("CWE-261", detect_cwe_261),
    ("CWE-262", detect_cwe_262),
    ("CWE-263", detect_cwe_263),
    ("CWE-266", detect_cwe_266),
    ("CWE-267", detect_cwe_267),
    ("CWE-268", detect_cwe_268),
    ("CWE-270", detect_cwe_270),
    ("CWE-272", detect_cwe_272),
    ("CWE-273", detect_cwe_273),
    ("CWE-274", detect_cwe_274),
    ("CWE-276", detect_cwe_276),
    ("CWE-277", detect_cwe_277),
    ("CWE-278", detect_cwe_278),
    ("CWE-279", detect_cwe_279),
    ("CWE-280", detect_cwe_280),
    ("CWE-281", detect_cwe_281),
    ("CWE-283", detect_cwe_283),
    ("CWE-289", detect_cwe_289),
    ("CWE-290", detect_cwe_290),
    ("CWE-294", detect_cwe_294),
    ("CWE-301", detect_cwe_301),
    ("CWE-303", detect_cwe_303),
    ("CWE-305", detect_cwe_305),
    ("CWE-306", detect_cwe_306),
    ("CWE-307", detect_cwe_307),
    ("CWE-308", detect_cwe_308),
    ("CWE-309", detect_cwe_309),
    ("CWE-312", detect_cwe_312),
    ("CWE-319", detect_cwe_319),
    ("CWE-322", detect_cwe_322),
    ("CWE-323", detect_cwe_323),
    ("CWE-324", detect_cwe_324),
    ("CWE-325", detect_cwe_325),
    ("CWE-328", detect_cwe_328),
    ("CWE-331", detect_cwe_331),
    ("CWE-334", detect_cwe_334),
    ("CWE-335", detect_cwe_335),
    ("CWE-338", detect_cwe_338),
    ("CWE-341", detect_cwe_341),
    ("CWE-342", detect_cwe_342),
    ("CWE-343", detect_cwe_343),
    ("CWE-344", detect_cwe_344),
    ("CWE-346", detect_cwe_346),
    ("CWE-347", detect_cwe_347),
    ("CWE-349", detect_cwe_349),
    ("CWE-353", detect_cwe_353),
    ("CWE-356", detect_cwe_356),
    ("CWE-358", detect_cwe_358),
    ("CWE-359", detect_cwe_359),
    ("CWE-360", detect_cwe_360),
    ("CWE-366", detect_cwe_366),
    ("CWE-367", detect_cwe_367),
    ("CWE-368", detect_cwe_368),
    ("CWE-378", detect_cwe_378),
    ("CWE-379", detect_cwe_379),
    ("CWE-385", detect_cwe_385),
    ("CWE-393", detect_cwe_393),
    ("CWE-403", detect_cwe_403),
    ("CWE-408", detect_cwe_408),
    ("CWE-412", detect_cwe_412),
    ("CWE-420", detect_cwe_420),
    ("CWE-421", detect_cwe_421),
    ("CWE-425", detect_cwe_425),
    ("CWE-426", detect_cwe_426),
    ("CWE-427", detect_cwe_427),
    ("CWE-434", detect_cwe_434),
    ("CWE-552", detect_cwe_552),
    ("CWE-565", detect_cwe_565),
    ("CWE-454", detect_cwe_454),
    ("CWE-455", detect_cwe_455),
    ("CWE-459", detect_cwe_459),
    ("CWE-472", detect_cwe_472),
    ("CWE-488", detect_cwe_488),
    ("CWE-494", detect_cwe_494),
    ("CWE-497", detect_cwe_497),
    ("CWE-501", detect_cwe_501),
    ("CWE-502", detect_cwe_502),
    ("CWE-515", detect_cwe_515),
    ("CWE-521", detect_cwe_521),
    ("CWE-523", detect_cwe_523),
    ("CWE-524", detect_cwe_524),
    ("CWE-538", detect_cwe_538),
    ("CWE-544", detect_cwe_544),
    ("CWE-547", detect_cwe_547),
    ("CWE-549", detect_cwe_549),
    ("CWE-551", detect_cwe_551),
    ("CWE-601", detect_cwe_601),
    ("CWE-603", detect_cwe_603),
    ("CWE-605", detect_cwe_605),
    ("CWE-611", detect_cwe_611),
    ("CWE-613", detect_cwe_613),
    ("CWE-618", detect_cwe_618),
    ("CWE-619", detect_cwe_619),
    ("CWE-620", detect_cwe_620),
    ("CWE-639", detect_cwe_639),
    ("CWE-640", detect_cwe_640),
    ("CWE-645", detect_cwe_645),
    ("CWE-648", detect_cwe_648),
    ("CWE-649", detect_cwe_649),
    ("CWE-653", detect_cwe_653),
    ("CWE-654", detect_cwe_654),
    ("CWE-656", detect_cwe_656),
    ("CWE-708", detect_cwe_708),
    ("CWE-756", detect_cwe_756),
    ("CWE-765", detect_cwe_765),
    ("CWE-778", detect_cwe_778),
    ("CWE-783", detect_cwe_783),
    ("CWE-798", detect_cwe_798),
    ("CWE-820", detect_cwe_820),
    ("CWE-821", detect_cwe_821),
    ("CWE-826", detect_cwe_826),
    ("CWE-829", detect_cwe_829),
    ("CWE-836", detect_cwe_836),
    ("CWE-838", detect_cwe_838),
    ("CWE-841", detect_cwe_841),
    ("CWE-842", detect_cwe_842),
    ("CWE-909", detect_cwe_909),
    ("CWE-915", detect_cwe_915),
    ("CWE-916", detect_cwe_916),
    ("CWE-917", detect_cwe_917),
    ("CWE-918", detect_cwe_918),
    ("CWE-921", detect_cwe_921),
    ("CWE-924", detect_cwe_924),
    ("CWE-940", detect_cwe_940),
    ("CWE-941", detect_cwe_941),
    ("CWE-1051", detect_cwe_1051),
    ("CWE-1052", detect_cwe_1052),
    ("CWE-1067", detect_cwe_1067),
    ("CWE-1173", detect_cwe_1173),
    ("CWE-1125", detect_cwe_1125),
    ("CWE-1204", detect_cwe_1204),
    ("CWE-1220", detect_cwe_1220),
    ("CWE-1230", detect_cwe_1230),
    ("CWE-1236", detect_cwe_1236),
    ("CWE-1240", detect_cwe_1240),
    ("CWE-1265", detect_cwe_1265),
    ("CWE-1286", detect_cwe_1286),
    ("CWE-1289", detect_cwe_1289),
    ("CWE-1322", detect_cwe_1322),
    ("CWE-1327", detect_cwe_1327),
    ("CWE-1333", detect_cwe_1333),
    ("CWE-1389", detect_cwe_1389),
    ("CWE-1392", detect_cwe_1392),
    ("CWE-807", detect_cwe_807),
];

impl Rule for GoCweScan {
    fn metadata(&self) -> RuleMetadata {
        META_CWE_15
    }
}

impl Detector for GoCweScan {
    fn language(&self) -> LanguageId {
        LanguageId::Go
    }

    fn rule_ids(&self) -> &'static [&'static str] {
        GO_CWE_RULE_IDS
    }

    fn run(&self, ctx: &ScanContext, unit: &ParsedUnit, out: &mut Vec<Finding>) {
        if !DETECTORS.iter().any(|(rule_id, _)| ctx.allows(rule_id)) {
            return;
        }

        let facts = build_go_unit_facts(unit);
        for (rule_id, detector) in DETECTORS {
            if ctx.allows(rule_id) {
                detector(unit, &facts, out);
            }
        }
    }
}
