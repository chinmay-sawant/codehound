//! Taint-based detectors for CWE rules.

mod cwe_22;
mod cwe_78;
mod cwe_79;
mod cwe_89;
mod cwe_90;
mod cwe_91;
mod evidence;

pub use cwe_22::detect_cwe_22_taint;
pub use cwe_78::detect_cwe_78_taint;
pub use cwe_79::detect_cwe_79_taint;
pub use cwe_89::detect_cwe_89_taint;
pub use cwe_90::detect_cwe_90_taint;
pub use cwe_91::detect_cwe_91_taint;
