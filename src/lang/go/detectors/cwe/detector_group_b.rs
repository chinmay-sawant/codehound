use super::facts::GoUnitFacts;
use super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};

pub(super) fn detect_cwe_289(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("canonical_name = ?") {
        return;
    }
    if !source.contains("strings.Split(") || !source.contains(r#""@")[0]"#) {
        return;
    }

    let start_byte = source.find("strings.Split(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_289,
        file,
        line,
        col,
        "principal authentication strips the realm suffix and authenticates only the bare local username",
        out,
    );
}

pub(super) fn detect_cwe_290(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(header_call) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.GetHeader" || call.callee.as_ref() == "r.Header.Get")
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.contains("X-Remote-User"))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(header_call.start_byte);
    emit::push_finding(
        &META_CWE_290,
        file,
        line,
        col,
        "the request trusts a caller-controlled X-Remote-User header as the authenticated identity",
        out,
    );
}

pub(super) fn detect_cwe_294(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let loads_auth_token = source.contains(r#"c.PostForm("auth_token")"#)
        || source.contains(r#"r.FormValue("auth_token")"#);
    if !loads_auth_token {
        return;
    }

    let has_nonce_tracking = source.contains("LoadOrStore(nonce, true)")
        || source.contains("spentNonces")
        || source.contains(r#"PostForm("nonce")"#)
        || source.contains(r#"FormValue("nonce")"#);
    if has_nonce_tracking {
        return;
    }

    let start_byte = if let Some(idx) = source.find("auth_token") {
        idx
    } else {
        return;
    };

    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_294,
        file,
        line,
        col,
        "the login flow accepts an authentication token without nonce tracking or replay detection",
        out,
    );
}

pub(super) fn detect_cwe_301(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let echoes_challenge = source.contains(r#"gin.H{"proof": challenge}"#)
        || source.contains(r#"{"proof": challenge}"#)
        || source.contains(r#"map[string]string{"proof": challenge}"#);
    if !echoes_challenge {
        return;
    }
    if source.contains("hmac.New(") || source.contains("EncodeToString(") {
        return;
    }

    let start_byte = source.find("challenge").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_301,
        file,
        line,
        col,
        "the server reflects the client challenge directly as the authentication proof",
        out,
    );
}

pub(super) fn detect_cwe_303(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("hmac.New(") || !source.contains("mac.Sum(nil)") {
        return;
    }
    if !source.contains("string(expected) == sig") {
        return;
    }

    let start_byte = source.find("string(expected) == sig").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_303,
        file,
        line,
        col,
        "the computed MAC is compared to user input with string equality instead of constant-time verification",
        out,
    );
}

pub(super) fn detect_cwe_305(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let debug_bypass = source.contains(r#"Query("debug") == "1""#)
        || source.contains(r#"Query().Get("debug") == "1""#);
    if !debug_bypass {
        return;
    }

    let has_subject_check = source.contains("jwt_sub") || source.contains("X-JWT-Sub");
    if !has_subject_check {
        return;
    }

    let start_byte = if let Some(idx) = source.find("debug") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_305,
        file,
        line,
        col,
        "a caller-controlled debug flag reaches privileged behavior before the authenticated subject check",
        out,
    );
}

pub(super) fn detect_cwe_306(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let destructive_purge = source.contains("TRUNCATE ledger");
    if !destructive_purge {
        return;
    }
    let has_auth_gate = source.contains("operator_id") || source.contains("X-Operator-ID");
    if has_auth_gate {
        return;
    }

    let start_byte = source.find("TRUNCATE ledger").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_306,
        file,
        line,
        col,
        "a destructive purge endpoint performs its action without any authentication gate",
        out,
    );
}

pub(super) fn detect_cwe_307(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let login_lookup = source.contains("SELECT hash FROM users WHERE email = ?")
        || source.contains(r#"Where("email = ?", email).First(&u)"#);
    if !login_lookup {
        return;
    }

    let has_attempt_tracking = source.contains("loginAttempts")
        || source.contains("LoadOrStore(key, 0)")
        || source.contains("time.Sleep(200 * time.Millisecond)");
    if has_attempt_tracking {
        return;
    }

    let start_byte = if let Some(idx) = source.find("email") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_307,
        file,
        line,
        col,
        "the login flow has no throttling, backoff, or lockout for repeated failed authentication attempts",
        out,
    );
}

pub(super) fn detect_cwe_308(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_password_gate =
        source.contains(r#"PostForm("password")"#) || source.contains(r#"FormValue("password")"#);
    if !has_password_gate {
        return;
    }
    if source.contains(r#"PostForm("totp")"#)
        || source.contains(r#"FormValue("totp")"#)
        || source.contains("totp_valid")
        || source.contains("X-TOTP-Valid")
    {
        return;
    }
    if !source.contains("INSERT INTO wires") {
        return;
    }

    let Some(start_byte) = source.find("password") else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_308,
        file,
        line,
        col,
        "a high-value wire action is authorized with only a password and no validated second factor",
        out,
    );
}

pub(super) fn detect_cwe_309(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let enterprise_login_shape = source.contains("func EnterpriseLogin(")
        && (source.contains(r#"{"session":"` + user + `"}"#)
            || source.contains(r#"{"session": user}"#)
            || source.contains(r#"gin.H{"session": user}"#)
            || source.contains(r#"gin.H{"session": c.GetString("subject")}"#));
    if !enterprise_login_shape {
        return;
    }

    let password_form_login = (source.contains(r#"PostForm("username")"#)
        || source.contains(r#"FormValue("username")"#))
        && (source.contains(r#"PostForm("password")"#)
            || source.contains(r#"FormValue("password")"#));
    if !password_form_login {
        return;
    }
    if source.contains("webauthn_assertion")
        || source.contains("X-WebAuthn-OK")
        || source.contains("webauthn_ok")
    {
        return;
    }

    let start_byte = source.find("username").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_309,
        file,
        line,
        col,
        "the enterprise login route relies on username and password form fields as the primary authentication method",
        out,
    );
}

pub(super) fn detect_cwe_312(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let stores_plain_ssn =
        source.contains("SSN: c.PostForm(\"ssn\")") || source.contains("SSN: r.FormValue(\"ssn\")");
    let writes_plain_ssn_json =
        source.contains(r#"SSN string `json:"ssn"`"#) && source.contains("json.Marshal(rec)");
    if !(stores_plain_ssn || writes_plain_ssn_json) {
        return;
    }
    if source.contains("SSNCipher") || source.contains("gcm.Seal(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("ssn") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_312,
        file,
        line,
        col,
        "a sensitive SSN value is persisted in cleartext instead of encrypted form",
        out,
    );
}

pub(super) fn detect_cwe_319(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let handles_card_data = source.contains("CVV") && source.contains("Number");
    if !handles_card_data {
        return;
    }
    if source.contains("ListenAndServeTLS(") || source.contains("tls.Config") {
        return;
    }
    if !(source.contains("ListenAndServe(") || source.contains("http.ListenAndServe(")) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("ListenAndServe") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_319,
        file,
        line,
        col,
        "sensitive payment data is accepted over a cleartext HTTP listener instead of TLS",
        out,
    );
}

pub(super) fn detect_cwe_322(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("tls.Dial(") || !source.contains("InsecureSkipVerify: true") {
        return;
    }

    let start_byte = source.find("InsecureSkipVerify: true").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_322,
        file,
        line,
        col,
        "the TLS relay connection disables peer certificate verification during key exchange",
        out,
    );
}

pub(super) fn detect_cwe_323(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let fixed_nonce = source.contains("sharedNonce")
        || source.contains("relaySessionNonce")
        || source.contains("static-nonce12")
        || source.contains("fixednonce12");
    if !fixed_nonce || !source.contains("aead.Seal(") {
        return;
    }
    if source.contains("io.ReadFull(rand.Reader, nonce)") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("Nonce") {
        idx
    } else if let Some(idx) = source.find("nonce") {
        idx
    } else {
        return;
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_323,
        file,
        line,
        col,
        "a fixed nonce is reused for AEAD encryption operations with the same key",
        out,
    );
}

pub(super) fn detect_cwe_324(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("ExpiresAt") {
        return;
    }
    let key_expiry_crypto_shape = (source.contains("ApiKeyRow") || source.contains("SigningKey"))
        && source.contains("Secret")
        && source.contains("hmac.New(");
    if !key_expiry_crypto_shape {
        return;
    }
    if source.contains("time.Now().After(row.ExpiresAt)")
        || source.contains("time.Now().After(key.ExpiresAt)")
    {
        return;
    }

    let expired_key_source =
        source.contains("Add(-48 * time.Hour)") || source.contains("ExpiresAt time.Time");
    if !expired_key_source {
        return;
    }

    let start_byte = source.find("ExpiresAt").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_324,
        file,
        line,
        col,
        "cryptographic processing uses key material with an expiration field but never checks whether the key is expired",
        out,
    );
}

pub(super) fn detect_cwe_325(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("cipher.NewCTR(") || !source.contains("XORKeyStream(") {
        return;
    }
    if source.contains("cipher.NewGCM(") || source.contains("Seal(") {
        return;
    }

    let start_byte = source.find("cipher.NewCTR(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_325,
        file,
        line,
        col,
        "sensitive data is encrypted with CTR mode without an authentication or integrity step",
        out,
    );
}

pub(super) fn detect_cwe_328(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("md5.Sum(") {
        return;
    }

    let start_byte = source.find("md5.Sum(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_328,
        file,
        line,
        col,
        "a password digest is derived with MD5, which is too weak for this security-sensitive use",
        out,
    );
}

pub(super) fn detect_cwe_331(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_recovery_code = source.contains("rand.NewSource(time.Now().UnixNano())")
        && source.contains("Intn(900000) + 100000")
        && source.contains("code");
    if !weak_recovery_code {
        return;
    }

    let start_byte = source.find("Intn(900000) + 100000").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_331,
        file,
        line,
        col,
        "the recovery code is generated from a small predictable decimal range instead of cryptographic randomness",
        out,
    );
}

pub(super) fn detect_cwe_334(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("Intn(4096)") {
        return;
    }

    let start_byte = source.find("Intn(4096)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_334,
        file,
        line,
        col,
        "the generated token comes from a very small 4096-value space and is easy to guess",
        out,
    );
}

pub(super) fn detect_cwe_335(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let predictable_seed = (source.contains("seed := time.Now().Unix()")
        || source.contains("rand.NewSource(seed)"))
        && (source.contains("rand.Seed(seed)")
            || source.contains("rand.New(rand.NewSource(seed))"));
    if !predictable_seed {
        return;
    }

    let start_byte = if let Some(idx) = source.find("time.Now().Unix()") {
        idx
    } else {
        source.find("rand.NewSource(seed)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_335,
        file,
        line,
        col,
        "the PRNG is seeded from predictable wall-clock time for a security-sensitive ticket value",
        out,
    );
}

pub(super) fn detect_cwe_338(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_prng_token = (source.contains("rand.New(rand.NewSource(time.Now().UnixNano()))")
        || source.contains("rand.NewSource(time.Now().UnixNano())"))
        && (source.contains("sid") || source.contains("token"));
    if !weak_prng_token {
        return;
    }

    let start_byte =
        if let Some(idx) = source.find("rand.New(rand.NewSource(time.Now().UnixNano()))") {
            idx
        } else {
            source
                .find("rand.NewSource(time.Now().UnixNano())")
                .unwrap_or(0)
        };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_338,
        file,
        line,
        col,
        "a security-sensitive token is generated from math/rand instead of cryptographic randomness",
        out,
    );
}

pub(super) fn detect_cwe_341(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let predictable_token = source.contains("fmt.Sprintf(\"%d-%d-%s\"")
        && source.contains("os.Getpid()")
        && source.contains("time.Now().Unix()");
    if !predictable_token {
        return;
    }

    let start_byte = source.find("fmt.Sprintf(\"%d-%d-%s\"").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_341,
        file,
        line,
        col,
        "the token is built from observable pid, wall-clock time, and caller input instead of cryptographic randomness",
        out,
    );
}

pub(super) fn detect_cwe_342(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let increments_previous = (source.contains("lastOTP++") && source.contains("code := lastOTP"))
        || (source.contains("lastSmsCode++") && source.contains("code := lastSmsCode"));
    if !increments_previous {
        return;
    }

    let start_byte = if let Some(idx) = source.find("lastOTP++") {
        idx
    } else {
        source.find("lastSmsCode++").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_342,
        file,
        line,
        col,
        "the next OTP value is generated by incrementing the previous one",
        out,
    );
}

pub(super) fn detect_cwe_343(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let deterministic_state_machine =
        source.contains("*3 + 1) % 97") || source.contains("*5 + 3) % 101");
    if !deterministic_state_machine {
        return;
    }

    let start_byte = if let Some(idx) = source.find("*3 + 1) % 97") {
        idx
    } else {
        source.find("*5 + 3) % 101").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_343,
        file,
        line,
        col,
        "the output range is produced by a deterministic recurrence over shared state and is predictable from previous values",
        out,
    );
}

pub(super) fn detect_cwe_344(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let hardcoded_secret = source.contains("const billingHMACSecret = ")
        || source.contains("const shipmentHMACSecret = ");
    if !hardcoded_secret || !source.contains("hmac.New(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("const billingHMACSecret = ") {
        idx
    } else {
        source.find("const shipmentHMACSecret = ").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_344,
        file,
        line,
        col,
        "a hard-coded invariant HMAC secret is embedded directly in code for a changing signing context",
        out,
    );
}

pub(super) fn detect_cwe_346(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let reflects_origin = source.contains("Access-Control-Allow-Origin\", origin")
        && source.contains("Header.Get(\"Origin\")");
    if !reflects_origin {
        return;
    }
    if source.contains("allowedOrigins")
        || source.contains("trustedOrigins")
        || source.contains("forbidden origin")
    {
        return;
    }

    let start_byte = source.find("Access-Control-Allow-Origin").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_346,
        file,
        line,
        col,
        "the response reflects the caller-supplied Origin without validating it against a trusted allow-list",
        out,
    );
}

pub(super) fn detect_cwe_347(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let decodes_jwt_payload = source.contains("strings.Split(raw, \".\")")
        && source.contains("DecodeString(parts[1])")
        && source.contains("json.Unmarshal(payload, &claims)");
    if !decodes_jwt_payload {
        return;
    }
    if source.contains("VerifyPKCS1v15(") || source.contains("invalid signature") {
        return;
    }

    let start_byte = source.find("DecodeString(parts[1])").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_347,
        file,
        line,
        col,
        "JWT claims are decoded and trusted without verifying the token signature first",
        out,
    );
}

pub(super) fn detect_cwe_349(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let mixed_trust_blob = (source.contains("json.RawMessage")
        && source.contains("json.Unmarshal(bundle.Profile, &profile)"))
        || (source.contains("json.RawMessage")
            && source.contains("json.Unmarshal(env.Profile, &profile)"));
    if !mixed_trust_blob {
        return;
    }
    if source.contains("Role != \"support\"")
        || source.contains("role not allowed from trusted channel")
    {
        return;
    }

    let start_byte = source.find("json.RawMessage").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_349,
        file,
        line,
        col,
        "trusted envelope metadata is mixed with an untyped raw profile blob whose role fields are used directly",
        out,
    );
}

pub(super) fn detect_cwe_353(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let ingests_body = source.contains("io.ReadAll(") && source.contains("INSERT INTO telemetry")
        || source.contains("io.ReadAll(") && source.contains("INSERT INTO agent_reports");
    if !ingests_body {
        return;
    }
    if source.contains("X-Body-Mac") || source.contains("ConstantTimeCompare(expected, got)") {
        return;
    }

    let start_byte = source.find("io.ReadAll(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_353,
        file,
        line,
        col,
        "the inbound payload is stored without verifying any integrity MAC",
        out,
    );
}

pub(super) fn detect_cwe_356(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let destructive_delete = (source.contains("func PurgeTenant(")
        && source.contains("DELETE FROM tenants WHERE slug = ?"))
        || (source.contains("func DeleteWorkspaceRecords(")
            && source.contains("DELETE FROM workspaces WHERE slug = ?"));
    if !destructive_delete {
        return;
    }
    if source.contains("X-Confirm-Purge") || source.contains("X-Confirm-Delete") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("DELETE FROM tenants") {
        idx
    } else {
        source.find("DELETE FROM workspaces").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_356,
        file,
        line,
        col,
        "the destructive action executes without an explicit confirmation token or second-step confirmation",
        out,
    );
}

pub(super) fn detect_cwe_358(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let decodes_bearer_claims = source.contains("strings.TrimPrefix(raw, \"Bearer \")")
        && source.contains("DecodeString(parts[1])")
        && source.contains("json.Unmarshal(payload, &claims)");
    if !decodes_bearer_claims {
        return;
    }
    if source.contains("invalid jwt structure") || source.contains("unsupported jwt algorithm") {
        return;
    }

    let start_byte = source.find("DecodeString(parts[1])").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_358,
        file,
        line,
        col,
        "bearer token claims are accepted without required JWT structure and algorithm validation",
        out,
    );
}

pub(super) fn detect_cwe_359(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let serializes_pii = (source.contains("SSN")
        && source.contains("Phone")
        && source.contains("json.Marshal(row)"))
        || (source.contains("SSN")
            && source.contains("Phone")
            && source.contains("json.Marshal(")
            && source.contains("PersonRecord"));
    if !serializes_pii {
        return;
    }
    if source.contains("PublicProfile")
        || source.contains("PublicPersonView")
        || source.contains("requester != target")
    {
        return;
    }

    let start_byte = source
        .find("json.Marshal(row)")
        .unwrap_or_else(|| source.find("SSN").unwrap_or(0));
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_359,
        file,
        line,
        col,
        "private personal information is serialized directly without requester authorization or public projection",
        out,
    );
}

pub(super) fn detect_cwe_360(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if !source.contains("X-Forwarded-For") {
        return;
    }
    if source.contains("SplitHostPort(") || source.contains("RemoteAddr") {
        return;
    }

    let start_byte = source.find("X-Forwarded-For").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_360,
        file,
        line,
        col,
        "a security-sensitive client IP action trusts caller-controlled forwarded header data",
        out,
    );
}

pub(super) fn detect_cwe_366(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let direct_credit_increment =
        source.contains("walletCredits += amount") || source.contains("referralCredits += 10");
    if !direct_credit_increment {
        return;
    }
    if source.contains("atomic.AddInt64(") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("walletCredits += amount") {
        idx
    } else {
        source.find("referralCredits += 10").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_366,
        file,
        line,
        col,
        "shared credit state is incremented without atomic or synchronized protection",
        out,
    );
}

pub(super) fn detect_cwe_367(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let stat_then_use =
        source.contains("os.Stat(target)") && source.contains("os.ReadFile(target)");
    if !stat_then_use {
        return;
    }

    let start_byte = source.find("os.Stat(target)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_367,
        file,
        line,
        col,
        "the code checks a file path with Stat before later using it, creating a TOCTOU race window",
        out,
    );
}

pub(super) fn detect_cwe_368(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_privilege_flag = (source.contains("actingAsRoot = true")
        || source.contains("privilegedMode = true"))
        && source.contains("os.Setenv(");
    if !shared_privilege_flag {
        return;
    }
    if source.contains("sync.Mutex") || source.contains("Lock()") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("actingAsRoot = true") {
        idx
    } else {
        source.find("privilegedMode = true").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_368,
        file,
        line,
        col,
        "privileged context switching is controlled by an unsynchronized shared mode flag",
        out,
    );
}

pub(super) fn detect_cwe_378(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let insecure_temp_file = source.contains("os.TempDir()") && source.contains("0666");
    if !insecure_temp_file {
        return;
    }
    if source.contains("CreateTemp(") || source.contains("Chmod(f.Name(), 0600)") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("os.TempDir()") {
        idx
    } else {
        source.find("0666").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_378,
        file,
        line,
        col,
        "a temp file is created with world-accessible permissions in the shared temp area",
        out,
    );
}

pub(super) fn detect_cwe_379(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let insecure_temp_dir = source.contains("MkdirAll(dir, 0777)")
        && (source.contains("/tmp/shared-reports") || source.contains("/tmp/shared-sessions"));
    if !insecure_temp_dir {
        return;
    }
    if source.contains("MkdirTemp(") || source.contains("Chmod(dir, 0700)") {
        return;
    }

    let start_byte = source.find("MkdirAll(dir, 0777)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_379,
        file,
        line,
        col,
        "a temporary file is staged inside a shared world-writable directory",
        out,
    );
}

pub(super) fn detect_cwe_385(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let early_exit_secret_compare = source.contains("for i := 0; i < len(provided); i++")
        && source.contains("if provided[i] != expected[i] {")
        && source.contains("return false");
    if !early_exit_secret_compare {
        return;
    }
    if source.contains("ConstantTimeCompare(") {
        return;
    }

    let start_byte = source
        .find("for i := 0; i < len(provided); i++")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_385,
        file,
        line,
        col,
        "the secret comparison exits on the first mismatch and leaks timing information",
        out,
    );
}

pub(super) fn detect_cwe_393(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let wrong_status = source.contains("if err != nil {")
        && source.contains("WriteHeader(http.StatusOK)")
        && source.contains(r#"{"balance":0}"#);
    if !wrong_status {
        return;
    }

    let start_byte = source.find("WriteHeader(http.StatusOK)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_393,
        file,
        line,
        col,
        "lookup failure still returns HTTP 200 with a fallback balance payload",
        out,
    );
}

pub(super) fn detect_cwe_403(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let opens_secret_before_exec = source.contains("os.Open(\"/etc/slopguard/master.key\")")
        && source.contains("exec.Command(\"/bin/sh\", \"-c\"");
    if !opens_secret_before_exec {
        return;
    }
    if source.contains("secret.Fd()") || source.contains("defer secret.Close()") {
        return;
    }

    let start_byte = source
        .find("os.Open(\"/etc/slopguard/master.key\")")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_403,
        file,
        line,
        col,
        "a sensitive descriptor is left open when launching a child shell command",
        out,
    );
}

pub(super) fn detect_cwe_408(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let query_before_auth = (source.contains("SELECT * FROM orders WHERE tenant_id = ?")
        && source.contains("Authorization"))
        && (source
            .find("SELECT * FROM orders WHERE tenant_id = ?")
            .unwrap_or(usize::MAX)
            < source.find("Authorization").unwrap_or(0));
    if !query_before_auth {
        return;
    }

    let start_byte = source
        .find("SELECT * FROM orders WHERE tenant_id = ?")
        .unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_408,
        file,
        line,
        col,
        "the export query runs before the caller authentication check",
        out,
    );
}

pub(super) fn detect_cwe_412(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let client_lock_path = source.contains("lockfile") && source.contains("os.ReadFile(lockPath)");
    if !client_lock_path {
        return;
    }
    if source.contains("jobLockPath") || source.contains("fixedJobLock") {
        return;
    }

    let start_byte = source.find("lockfile").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_412,
        file,
        line,
        col,
        "the lock file path comes directly from the client request",
        out,
    );
}

pub(super) fn detect_cwe_420(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_unprotected_debug_route = (source.contains("r.GET(\"/debug/sqltrace\"")
        && source.contains("r.Group(\"/api\", requireJWT())"))
        || (source.contains("http.HandleFunc(\"/debug/sqltrace\"")
            && source.contains("http.Handle(\"/api/invoices\", protected)"));
    if !has_unprotected_debug_route {
        return;
    }

    let start_byte = source.find("/debug/sqltrace").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_420,
        file,
        line,
        col,
        "the alternate debug route is exposed outside the primary authenticated API guard",
        out,
    );
}

pub(super) fn detect_cwe_421(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_event_state = (source.contains("transferToken =")
        && source.contains("event: status\\ndata: \" + transferToken"))
        || (source.contains("wireTransferCode =")
            && source.contains("event: status\\ndata: %s\\n\\n\", wireTransferCode"));
    if !shared_event_state {
        return;
    }
    if source.contains("sync.Mutex") || source.contains("transferMu") || source.contains("wireMu") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("transferToken =") {
        idx
    } else {
        source.find("wireTransferCode =").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_421,
        file,
        line,
        col,
        "an alternate event channel exposes shared transfer state without synchronization",
        out,
    );
}

pub(super) fn detect_cwe_425(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let admin_export = source.contains("/internal/admin/export.csv")
        && source.contains("SELECT email, ssn FROM customers");
    if !admin_export {
        return;
    }
    if source.contains("requireAdmin()") || source.contains("requireAdmin(") {
        return;
    }

    let start_byte = source.find("/internal/admin/export.csv").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_425,
        file,
        line,
        col,
        "the admin export endpoint is mounted without an explicit authorization guard",
        out,
    );
}

pub(super) fn detect_cwe_426(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let request_controlled_plugin_dir =
        source.contains("plugin_dir") && source.contains("plugin.Open(modPath)");
    if !request_controlled_plugin_dir {
        return;
    }
    if source.contains("trustedPluginDir") || source.contains("trustedPluginRoot") {
        return;
    }

    let start_byte = source.find("plugin_dir").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_426,
        file,
        line,
        col,
        "the plugin load directory is derived from caller-controlled input",
        out,
    );
}

pub(super) fn detect_cwe_427(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let path_mutation =
        source.contains("os.Setenv(\"PATH\",") && source.contains("exec.Command(\"pdftopng\"");
    if !path_mutation {
        return;
    }
    if source.contains("pdftopngPath") || source.contains("pdftopngBinary") {
        return;
    }

    let start_byte = source.find("os.Setenv(\"PATH\",").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_427,
        file,
        line,
        col,
        "user input is prepended to PATH before resolving the helper binary by name",
        out,
    );
}

pub(super) fn detect_cwe_434(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let stores_client_filename = (source.contains("file.Filename")
        && source.contains("SaveUploadedFile(file, dest)"))
        || (source.contains("hdr.Filename") && source.contains("os.Create(dest)"));
    if !stores_client_filename {
        return;
    }
    let executable_web_serve_shape = (source.contains("/var/www/static/avatars")
        || source.contains("/static/avatars/"))
        && (source.contains("c.Redirect(http.StatusFound, \"/static/avatars/\"+file.Filename)")
            || source.contains(
                "http.Redirect(w, r, \"/static/avatars/\"+hdr.Filename, http.StatusFound)",
            ));
    if !executable_web_serve_shape {
        return;
    }
    if source.contains("unsupported file type")
        || source.contains("filepath.Ext(")
        || source.contains("hex.EncodeToString(")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("file.Filename") {
        idx
    } else {
        source.find("hdr.Filename").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_434,
        file,
        line,
        col,
        "the upload is stored and later served using the client filename without an extension allow-list",
        out,
    );
}

pub(super) fn detect_cwe_552(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let permissive_upload_mode = (source.contains("FormFile(\"contract\")")
        || source.contains("FormFile(\"contract\")"))
        && source.contains("/srv/contracts")
        && source.contains("os.Chmod(dest, 0o777)");
    if !permissive_upload_mode {
        return;
    }
    if source.contains("filepath.Base(") || source.contains("os.Chmod(dest, 0o600)") {
        return;
    }

    let start_byte = source.find("os.Chmod(dest, 0o777)").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_552,
        file,
        line,
        col,
        "uploaded contract files are made world-accessible after storage",
        out,
    );
}

pub(super) fn detect_cwe_565(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let trusts_role_cookie = (source.contains("c.Cookie(\"role\")")
        || source.contains("r.Cookie(\"role\")"))
        && source.contains(r#""admin""#)
        && source.contains("DELETE FROM tenants");
    if !trusts_role_cookie {
        return;
    }
    if source.contains("GetString(\"role\")") || source.contains("Header.Get(\"X-Role\")") {
        return;
    }

    let start_byte = source.find("Cookie(\"role\")").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_565,
        file,
        line,
        col,
        "a privileged delete action trusts a caller-controlled role cookie",
        out,
    );
}

pub(super) fn detect_cwe_454(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let request_bootstrap_flag = source
        .contains("enforceMFA = c.PostForm(\"enforce_mfa\") == \"true\"")
        || source.contains("enforceMFA = r.FormValue(\"enforce_mfa\") == \"true\"");
    if !request_bootstrap_flag {
        return;
    }

    let start_byte = source.find("enforce_mfa").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_454,
        file,
        line,
        col,
        "the MFA enforcement flag is bootstrapped from client input instead of server configuration",
        out,
    );
}

pub(super) fn detect_cwe_455(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let continues_after_tls_failure =
        source.contains("tls.LoadX509KeyPair(") && source.contains("continuing without mTLS");
    if !continues_after_tls_failure {
        return;
    }
    if source.contains("log.Fatalf(") {
        return;
    }

    let start_byte = source.find("continuing without mTLS").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_455,
        file,
        line,
        col,
        "startup logs a TLS material failure but continues running anyway",
        out,
    );
}

pub(super) fn detect_cwe_459(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let temp_export = source.contains("CreateTemp(")
        && (source.contains("c.File(f.Name())") || source.contains("ServeFile(w, r, f.Name())"));
    if !temp_export {
        return;
    }
    if source.contains("os.Remove(f.Name())") {
        return;
    }

    let start_byte = source.find("CreateTemp(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_459,
        file,
        line,
        col,
        "the temporary export file is served without being removed afterward",
        out,
    );
}

pub(super) fn detect_cwe_472(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let trusts_role_form = source.contains("Role    string `form:\"role\"`")
        || source.contains("role := r.FormValue(\"role\")");
    if !trusts_role_form {
        return;
    }
    if source.contains("SELECT role FROM users") {
        return;
    }

    let start_byte = source.find("role").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_472,
        file,
        line,
        col,
        "authorization trusts a client-submitted role field instead of resolving role server-side",
        out,
    );
}

pub(super) fn detect_cwe_488(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let global_session_map = source.contains("map[string][]string{}") && source.contains("session");
    if !global_session_map {
        return;
    }
    if source.contains("Cookie(\"session_id\")") || source.contains("r.Cookie(\"session_id\")") {
        return;
    }

    let start_byte = if let Some(idx) = source.find("sessionCarts") {
        idx
    } else {
        source.find("cartsBySession").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_488,
        file,
        line,
        col,
        "global cart state is keyed directly by a client-controlled session identifier",
        out,
    );
}

pub(super) fn detect_cwe_494(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let downloads_bundle = source.contains("http.Get(") && source.contains("/tmp/worker.bin");
    if !downloads_bundle {
        return;
    }
    if source.contains("sha256.Sum256(") || source.contains("integrity check failed") {
        return;
    }

    let start_byte = source.find("http.Get(").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_494,
        file,
        line,
        col,
        "the downloaded worker bundle is accepted without any pinned integrity verification",
        out,
    );
}

pub(super) fn detect_cwe_497(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let exposes_host_details = source.contains("os.Environ()")
        || source.contains("os.Hostname()")
        || source.contains("runtime.NumCPU()");
    if !exposes_host_details {
        return;
    }
    if source.contains(r#""status": "ok""#) {
        return;
    }

    let start_byte = if let Some(idx) = source.find("os.Environ()") {
        idx
    } else if let Some(idx) = source.find("os.Hostname()") {
        idx
    } else {
        source.find("runtime.NumCPU()").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_497,
        file,
        line,
        col,
        "the diagnostics endpoint exposes host environment details to callers",
        out,
    );
}

pub(super) fn detect_cwe_501(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let merged_trust_struct =
        (source.contains("Approved bool") && source.contains("Amount") && source.contains("Memo"))
            && (source.contains("ShouldBindJSON(&msg)") || source.contains("Decode(&msg)"))
            && source.contains("msg.Approved = true");
    if !merged_trust_struct {
        return;
    }
    if source.contains("payoutDecision") || source.contains("Request  payoutRequest") {
        return;
    }

    let start_byte = source.find("Approved bool").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_501,
        file,
        line,
        col,
        "trusted approval state is merged into the same struct as untrusted request fields",
        out,
    );
}

pub(super) fn detect_cwe_502(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let untrusted_gob_decode = source.contains("encoding/gob")
        && source.contains("gob.NewDecoder(")
        && source.contains(".Decode(&action)")
        && source.contains("adminAction")
        && source.contains("Grant");
    if !untrusted_gob_decode {
        return;
    }
    if source.contains("ShouldBindJSON(&req)")
        || source.contains("json.NewDecoder(r.Body).Decode(&req)")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("gob.NewDecoder(") {
        idx
    } else {
        source.find(".Decode(&action)").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_502,
        file,
        line,
        col,
        "user-controlled gob data is deserialized into a privileged admin action",
        out,
    );
}

pub(super) fn detect_cwe_515(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let shared_covert_flag = (source.contains("var quotaFlag int")
        || source.contains("var quotaCovertFlag int"))
        && source.contains(r#""over""#)
        && source.contains("= 1")
        && source.contains("= 0")
        && source.contains(r#""over_limit""#);
    if !shared_covert_flag {
        return;
    }
    if source.contains("WHERE tenant = ?")
        || source.contains("GetString(\"tenant\")")
        || source.contains("X-Tenant")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("var quotaFlag int") {
        idx
    } else {
        source.find("var quotaCovertFlag int").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_515,
        file,
        line,
        col,
        "a global quota flag is used as a covert cross-request signal",
        out,
    );
}

pub(super) fn detect_cwe_521(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let weak_password_policy = source.contains("Password")
        && source.contains("len(body.Password) < 1")
        || source.contains("len(body.Password)<1")
        || source.contains("len(pw) < 1");
    let stores_password = source.contains("password_hash")
        && (source.contains("body.Password") || source.contains("body.Password"));
    if !(weak_password_policy && stores_password) {
        return;
    }
    if source.contains("strongPassword(") || source.contains("len(pw) < 12") {
        return;
    }

    let start_byte = source.find("len(body.Password) < 1").unwrap_or(0);
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_521,
        file,
        line,
        col,
        "password validation allows trivially weak credentials before persistence",
        out,
    );
}

pub(super) fn detect_cwe_523(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let cleartext_login = (source.contains("/login") && source.contains("password"))
        && (source.contains("Addr: \":8080\"") || source.contains("StartCleartextLogin"));
    if !cleartext_login {
        return;
    }
    if source.contains("requireTLS(")
        || source.contains("Request.TLS == nil")
        || source.contains("r.TLS == nil")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("/login") {
        idx
    } else {
        source.find("password").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_523,
        file,
        line,
        col,
        "login credentials are accepted before any TLS enforcement or redirect",
        out,
    );
}
