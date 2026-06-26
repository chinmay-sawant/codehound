//! Taint-based detectors for the four rewritten CWE rules.

mod cwe_22;
mod cwe_78;
mod cwe_79;
mod cwe_89;
mod evidence;

pub use cwe_22::detect_cwe_22_taint;
pub use cwe_78::detect_cwe_78_taint;
pub use cwe_79::detect_cwe_79_taint;
pub use cwe_89::detect_cwe_89_taint;
