use codehound::core::ScanContext;
use codehound::engine::Analyzer;

fn main() -> Result<(), codehound::Error> {
    let analyzer = Analyzer::builder()
        .scan_context(ScanContext::default())
        .build();
    let paths: [&std::path::Path; 0] = [];
    let result = analyzer.analyze_paths(&paths, None)?;

    assert!(result.findings.is_empty());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn example_runs() {
        super::main().expect("library scan example");
    }
}
