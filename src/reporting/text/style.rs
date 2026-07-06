//! Plain-text reporter: style helpers (cfg-gated for terminal color support).

#[cfg(feature = "terminal-output")]
mod terminal {
    use crate::rules::Severity;
    use colored::Colorize;

    pub fn severity(s: Severity) -> colored::ColoredString {
        let raw = s.as_str();
        match s {
            Severity::Info => raw.cyan(),
            Severity::Low => raw.yellow(),
            Severity::Medium => raw.yellow().bold(),
            Severity::High => raw.red(),
            Severity::Critical => raw.red().bold(),
        }
    }

    pub fn rule_id(s: &str) -> colored::ColoredString {
        if s.starts_with("BP-") {
            s.magenta().bold()
        } else if s.starts_with("PERF-") {
            s.cyan().bold()
        } else {
            s.bold()
        }
    }
    pub fn dimmed(s: &str) -> colored::ColoredString {
        s.dimmed()
    }
    pub fn green_bold(s: &str) -> colored::ColoredString {
        s.green().bold()
    }
    pub fn cyan(s: &str) -> colored::ColoredString {
        s.cyan()
    }
}

#[cfg(not(feature = "terminal-output"))]
mod terminal {
    use crate::rules::Severity;

    pub fn severity(s: Severity) -> &'static str {
        s.as_str()
    }
    pub fn rule_id(s: &str) -> &str {
        s
    }
    pub fn dimmed(s: &str) -> &str {
        s
    }
    pub fn green_bold(s: &str) -> &str {
        s
    }
    pub fn cyan(s: &str) -> &str {
        s
    }
}

pub use terminal::*;
