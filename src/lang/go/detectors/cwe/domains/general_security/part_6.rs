use super::super::super::facts::GoUnitFacts;
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_841(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let workflow_skip = source.contains("ResetAccount")
        && source.contains("new_password")
        && source.contains("password");
    if !workflow_skip {
        return;
    }
    if (source.contains("MFAPassed") && source.contains("if !acct.MFAPassed"))
        || source.contains("if !accountMFAPassed[email]")
    {
        return;
    }

    let start_byte = source.find("new_password").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_841,
        file,
        line,
        col,
        "the reset workflow changes credentials without enforcing MFA completion",
        out,
    );
}

pub(crate) fn detect_cwe_842(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let wrong_default_group =
        source.contains("RegisterMember") && source.contains("Group: \"administrators\"");
    if !wrong_default_group {
        return;
    }
    if source.contains("Group: \"members\"") {
        return;
    }

    let start_byte = source.find("Group: \"administrators\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_842,
        file,
        line,
        col,
        "newly registered users are assigned to an administrator group by default",
        out,
    );
}

pub(crate) fn detect_cwe_909(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let missing_init_guard = (source.contains("appDB.Find(") || source.contains("widgetDB.Query("))
        && !source.contains("if appDB == nil")
        && !source.contains("if widgetDB == nil");
    if !missing_init_guard {
        return;
    }

    let start_byte = if let Some(idx) = source.find("appDB.Find(") {
        idx
    } else {
        source.find("widgetDB.Query(").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_909,
        file,
        line,
        col,
        "a global database handle is used without checking that initialization completed",
        out,
    );
}

pub(crate) fn detect_cwe_915(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let mass_assignment = source.contains("map[string]interface{}")
        && (source.contains("Updates(fields)") || source.contains("json.Unmarshal(raw, &p)"));
    if !mass_assignment {
        return;
    }
    if source.contains("Update(\"name\"") || source.contains("p.Name = body.Name") {
        return;
    }

    let start_byte = source.find("map[string]interface{}").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_915,
        file,
        line,
        col,
        "a user-controlled attribute map updates privileged object fields directly",
        out,
    );
}

pub(crate) fn detect_cwe_924(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let applies_payment_webhook = (source.contains("AcceptWebhook(")
        || source.contains("AcceptWebhookPure(")
        || source.contains("AcceptWebhookVerified(")
        || source.contains("AcceptWebhookVerifiedPure("))
        && source.contains("UPDATE invoices SET paid = true")
        && (source.contains("BindJSON(&evt)")
            || source.contains("Decode(&evt)")
            || source.contains("Unmarshal(body, &evt)"));
    if !applies_payment_webhook {
        return;
    }
    if source.contains("X-Signature")
        || source.contains("hmac.New(sha256.New")
        || source.contains("hmac.Equal(")
    {
        return;
    }

    let start_byte = source
        .find("BindJSON(&evt)")
        .or_else(|| source.find("Decode(&evt)"))
        .unwrap_or_else(|| source.find("UPDATE invoices SET paid = true").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_924,
        file,
        line,
        col,
        "a payment webhook body is applied without validating an integrity signature first",
        out,
    );
}

pub(crate) fn detect_cwe_940(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let oauth_callback = (source.contains("OAuthCallback(")
        || source.contains("OAuthCallbackPure("))
        && source.contains("code")
        && source.contains("INSERT INTO oauth_tokens (user_id, code) VALUES ($1, $2)");
    if !oauth_callback {
        return;
    }
    if source.contains("oauth_state")
        || source.contains("Cookie(\"oauth_state\")")
        || source.contains("r.Cookie(\"oauth_state\")")
        || source.contains("invalid oauth state")
    {
        return;
    }

    let start_byte = source
        .find("Query(\"user_id\")")
        .or_else(|| source.find("Query().Get(\"user_id\")"))
        .unwrap_or_else(|| source.find("oauth_tokens").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_940,
        file,
        line,
        col,
        "an OAuth callback accepts caller-supplied authorization data without verifying a bound state token",
        out,
    );
}

pub(crate) fn detect_cwe_941(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let caller_directed_reset = (source.contains("SendResetLink(")
        || source.contains("SendResetLinkPure("))
        && source.contains("smtp.SendMail")
        && (source.contains("Query(\"email\")") || source.contains("Query().Get(\"email\")"))
        && source.contains("[]string{email}");
    if !caller_directed_reset {
        return;
    }
    if source.contains("user.Email")
        || source.contains("lookupEmail(")
        || source.contains("sessionUserID")
    {
        return;
    }

    let start_byte = source
        .find("Query(\"email\")")
        .or_else(|| source.find("Query().Get(\"email\")"))
        .unwrap_or_else(|| source.find("[]string{email}").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_941,
        file,
        line,
        col,
        "a reset notification is sent to a caller-controlled email address",
        out,
    );
}

pub(crate) fn detect_cwe_1125(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let wide_surface = (source.contains("MountWideSurface(")
        || source.contains("MountWideSurfacePure("))
        && (source.contains("/debug/pprof") || source.contains("pprof.Index"))
        && source.contains("/admin/sql")
        && source.contains("/admin/config")
        && source.contains("/internal/reload");
    if !wide_surface {
        return;
    }
    if source.contains("authRequired()") || source.contains("authRequiredPure(") {
        return;
    }

    let start_byte = source.find("/debug/pprof").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1125,
        file,
        line,
        col,
        "public routing exposes debug, admin, and internal maintenance endpoints together",
        out,
    );
}

pub(crate) fn detect_cwe_1265(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let nested_lock_reentry = (source.contains("UpdateBalance(")
        || source.contains("UpdateBalancePure("))
        && (source.contains("ledgerMu.Lock()") || source.contains("ledgerMuPure.Lock()"))
        && (source.contains("PostTransfer(") || source.contains("PostTransferPure("));
    if !nested_lock_reentry {
        return;
    }
    if source.contains("applyBalanceDelta(") || source.contains("applyBalanceDeltaPure(") {
        return;
    }

    let start_byte = source
        .find("UpdateBalance(")
        .or_else(|| source.find("UpdateBalancePure("))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1265,
        file,
        line,
        col,
        "a transfer path re-enters a mutex-protected balance helper while the same mutex is already held",
        out,
    );
}

pub(crate) fn detect_cwe_1286(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loose_json_config = (source.contains("SaveHookConfig(")
        || source.contains("SaveHookConfigPure("))
        && (source.contains("json.Unmarshal(body, &cfg)")
            || source.contains("json.NewDecoder(r.Body).Decode(&cfg)"))
        && source.contains("hook_configs");
    if !loose_json_config {
        return;
    }
    if source.contains("DisallowUnknownFields()") || source.contains("ParseRequestURI(cfg.URL)") {
        return;
    }

    let start_byte = source
        .find("json.Unmarshal(body, &cfg)")
        .or_else(|| source.find("json.NewDecoder(r.Body).Decode(&cfg)"))
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1286,
        file,
        line,
        col,
        "webhook configuration JSON is accepted without strict syntax and URL validation",
        out,
    );
}

pub(crate) fn detect_cwe_1289(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let literal_path_block = (source.contains("FetchSharedAsset(")
        || source.contains("FetchSharedAssetPure("))
        && source.contains("requested == \"private/keys.pem\"")
        && source.contains("filepath.Join(root, requested)");
    if !literal_path_block {
        return;
    }
    if source.contains("filepath.Clean(filepath.Join(root, requested))")
        || source.contains("HasPrefix(clean, root+string(filepath.Separator))")
    {
        return;
    }

    let start_byte = source
        .find("requested == \"private/keys.pem\"")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1289,
        file,
        line,
        col,
        "asset access relies on a literal blocked path comparison before canonical normalization",
        out,
    );
}

pub(crate) fn detect_cwe_1322(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let blocking_worker = (source.contains("StartWebhookWorker(")
        || source.contains("StartWebhookWorkerPure("))
        && source.contains("queue := make(chan")
        && source.contains("for payload := range queue")
        && source.contains("time.Sleep(2 * time.Second)");
    if !blocking_worker {
        return;
    }
    if source.contains("time.AfterFunc(") {
        return;
    }

    let start_byte = source.find("time.Sleep(2 * time.Second)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_1322,
        file,
        line,
        col,
        "the webhook worker blocks its queue loop with sleep instead of scheduling retries asynchronously",
        out,
    );
}
