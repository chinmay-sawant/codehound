use codehound::rules::{
    ControlFlowKind, DetectorEvidence, LineCol, TaintHop, TaintSinkInfo, TaintSourceInfo,
};

#[test]
fn taint_flow_evidence_round_trips() {
    let evidence = DetectorEvidence::TaintFlow {
        source: TaintSourceInfo {
            kind: "UserInput".to_string(),
            function: "(*http.Request).FormValue".to_string(),
            variable: "userID".to_string(),
        },
        sink: TaintSinkInfo::new("SQLQuery", "(*sql.DB).Query"),
        hops: 2,
        sanitized: false,
    };

    let parsed: DetectorEvidence =
        serde_json::from_str(&serde_json::to_string(&evidence).unwrap()).unwrap();

    assert_eq!(parsed, evidence);
}

#[test]
fn taint_flow_with_hops_includes_hop_details_in_json() {
    let evidence = DetectorEvidence::TaintFlow {
        source: TaintSourceInfo {
            kind: "UserInput".into(),
            function: "r.URL.Query".into(),
            variable: "userInput".into(),
        },
        sink: TaintSinkInfo {
            kind: "FileOpen".into(),
            function: "openFile".into(),
            hop_details: vec![TaintHop {
                function: "openFile".into(),
                kind: "FileOpen".into(),
                variable: "filename".into(),
                file: "handler.go".into(),
                line: 42,
            }],
        },
        hops: 1,
        sanitized: false,
    };

    let json = serde_json::to_string(&evidence).unwrap();
    assert!(
        json.contains("\"hop_details\""),
        "JSON should contain hop_details: {json}"
    );
    assert!(
        json.contains("\"handler.go\""),
        "JSON should contain hop file: {json}"
    );
    assert!(
        json.contains("\"openFile\""),
        "JSON should contain hop function: {json}"
    );

    // Round-trip should preserve hop_details.
    let parsed: DetectorEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, evidence);
}

#[test]
fn control_flow_issue_evidence_round_trips() {
    let evidence = DetectorEvidence::ControlFlowIssue {
        control_flow_kind: ControlFlowKind::LoopBodyAllocation,
        location: LineCol {
            line: 20,
            column: 9,
        },
    };

    let parsed: DetectorEvidence =
        serde_json::from_str(&serde_json::to_string(&evidence).unwrap()).unwrap();

    assert_eq!(parsed, evidence);
}
