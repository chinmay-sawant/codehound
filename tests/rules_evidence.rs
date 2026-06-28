use slopguard::rules::{
    ControlFlowKind, DetectorEvidence, LineCol, TaintSinkInfo, TaintSourceInfo,
};

#[test]
fn dangerous_call_evidence_round_trips() {
    let evidence = DetectorEvidence::DangerousCall {
        function: "exec.Command".to_string(),
        argument_index: Some(1),
    };

    let json = serde_json::to_string(&evidence).unwrap();
    let parsed: DetectorEvidence = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed, evidence);
    assert!(json.contains("\"kind\":\"DangerousCall\""), "{json}");
}

#[test]
fn taint_flow_evidence_round_trips() {
    let evidence = DetectorEvidence::TaintFlow {
        source: TaintSourceInfo {
            kind: "UserInput".to_string(),
            function: "(*http.Request).FormValue".to_string(),
            variable: "userID".to_string(),
        },
        sink: TaintSinkInfo {
            kind: "SQLQuery".to_string(),
            function: "(*sql.DB).Query".to_string(),
        },
        hops: 2,
        sanitized: false,
    };

    let parsed: DetectorEvidence =
        serde_json::from_str(&serde_json::to_string(&evidence).unwrap()).unwrap();

    assert_eq!(parsed, evidence);
}

#[test]
fn missing_config_evidence_round_trips() {
    let evidence = DetectorEvidence::DangerousCall {
        function: "ServerConfig.TLSConfig".into(),
        argument_index: None,
    };

    let parsed: DetectorEvidence =
        serde_json::from_str(&serde_json::to_string(&evidence).unwrap()).unwrap();

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
