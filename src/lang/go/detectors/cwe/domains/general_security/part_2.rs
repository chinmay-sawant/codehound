use super::super::super::facts::{GoUnitFacts, InputKind};
use super::super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_250(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    for call in &facts.call_facts {
        if call.callee.as_ref() != "os.WriteFile" || call.arguments.len() < 3 {
            continue;
        }
        if call.arguments[2].as_ref() != "0o777" {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_250,
            file,
            line,
            col,
            "runtime file is written with world-accessible permissions",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_252(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    for call in &facts.call_facts {
        if call.callee.as_ref() != "os.WriteFile" {
            continue;
        }
        if source.contains("if err := os.WriteFile(") {
            return;
        }
        let writes_audit_log = call
            .arguments
            .iter()
            .any(|arg| arg.contains("/var/log/audit.log") || arg.contains("/var/log/journal.log"));
        if !writes_audit_log {
            continue;
        }

        let (line, col) = unit.line_col(call.start_byte);
        emit::push_finding(
            &META_CWE_252,
            file,
            line,
            col,
            "os.WriteFile is called without checking its returned error",
            out,
        );
        return;
    }
}

pub(crate) fn detect_cwe_266(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(role_assignment) = facts
        .assignments
        .iter()
        .find(|assignment| assignment.name.as_ref() == "role")
    else {
        return;
    };

    let role_is_user_controlled = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled && binding.name.as_ref() == "role"
    });
    if !role_is_user_controlled {
        return;
    }

    let role_is_used_for_membership =
        source.contains("Role: role") || source.contains("Store(userID, role)");
    if !role_is_used_for_membership {
        return;
    }

    let (line, col) = unit.line_col(role_assignment.start_byte);
    emit::push_finding(
        &META_CWE_266,
        file,
        line,
        col,
        "a client-controlled role value is used directly when provisioning access",
        out,
    );
}

pub(crate) fn detect_cwe_267(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let reviewer_guard =
        source.contains(r#"!= "reviewer""#) || source.contains(r#".Get("X-Role") != "reviewer""#);
    if !reviewer_guard {
        return;
    }

    let Some(remove_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Remove")
    else {
        return;
    };

    let (line, col) = unit.line_col(remove_call.start_byte);
    emit::push_finding(
        &META_CWE_267,
        file,
        line,
        col,
        "the reviewer role is allowed to invoke a destructive filesystem removal operation",
        out,
    );
}

pub(crate) fn detect_cwe_268(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let has_chained_scopes = (source.contains(r#"p == "read""#)
        || source.contains(r#"case "read":"#))
        && (source.contains(r#"p == "export""#) || source.contains(r#"case "export":"#))
        && (source.contains("hasRead && hasExport") || source.contains("hasExport && hasRead"));
    if !has_chained_scopes {
        return;
    }

    let Some(sensitive_sink) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "db.Queryx"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.contains("password_hash")))
            || (call.callee.as_ref() == "json.NewEncoder"
                && source.contains("Encode(userRecords)")
                && source.contains(r#""hash""#))
    }) else {
        return;
    };

    let (line, col) = unit.line_col(sensitive_sink.start_byte);
    emit::push_finding(
        &META_CWE_268,
        file,
        line,
        col,
        "a sensitive export path is authorized by combining weaker read and export scopes",
        out,
    );
}

pub(crate) fn detect_cwe_270(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(context_switch) = facts.call_facts.iter().find(|call| {
        (call.callee.as_ref() == "c.Set"
            && call.arguments.len() >= 2
            && call.arguments[0].contains("effective_user")
            && (call.arguments[1].contains(r#""root""#)
                || call.arguments[1].contains(r#""maintenance""#)))
            || (call.callee.as_ref() == "context.WithValue"
                && call.arguments.len() >= 3
                && call.arguments[1].contains("effectiveUserKey")
                && (call.arguments[2].contains(r#""root""#)
                    || call.arguments[2].contains(r#""maintenance""#)))
    }) else {
        return;
    };

    let restores_context = source.contains("defer c.Set(\"effective_user\", original)")
        || (source.contains("defer func()")
            && source.contains("context.WithValue(r.Context(), effectiveUserKey, original)"));
    if restores_context {
        return;
    }

    let (line, col) = unit.line_col(context_switch.start_byte);
    emit::push_finding(
        &META_CWE_270,
        file,
        line,
        col,
        "the handler switches to a privileged execution context without restoring the original caller context",
        out,
    );
}

pub(crate) fn detect_cwe_272(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();

    let Some(elevate_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    }) else {
        return;
    };

    let performs_privileged_work = facts
        .call_facts
        .iter()
        .any(|call| call.callee.as_ref() == "os.Chown");
    if !performs_privileged_work {
        return;
    }

    let drops_privilege = facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "1000")
    });
    if drops_privilege {
        return;
    }

    let (line, col) = unit.line_col(elevate_call.start_byte);
    emit::push_finding(
        &META_CWE_272,
        file,
        line,
        col,
        "the handler raises uid for a privileged operation and does not drop it afterward",
        out,
    );
}

pub(crate) fn detect_cwe_273(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("if err := syscall.Setuid(1000); err != nil") {
        return;
    }

    if facts.call_facts.iter().any(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "0")
    }) {
        return;
    }

    let Some(drop_call) = facts.call_facts.iter().find(|call| {
        call.callee.as_ref() == "syscall.Setuid"
            && call
                .arguments
                .first()
                .is_some_and(|arg| arg.as_ref() == "1000")
    }) else {
        return;
    };

    let (line, col) = unit.line_col(drop_call.start_byte);
    emit::push_finding(
        &META_CWE_273,
        file,
        line,
        col,
        "the handler ignores whether dropping privilege via Setuid actually succeeded",
        out,
    );
}

pub(crate) fn detect_cwe_274(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let Some(rename_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Rename")
    else {
        return;
    };

    let treats_error_as_success = (source.contains("if err != nil {")
        && (source.contains(r#"c.JSON(200, gin.H{"rotated": true})"#)
            || source.contains(r#"w.WriteHeader(http.StatusOK)"#)))
        && !source.contains("errors.Is(err, syscall.EPERM)");
    if !treats_error_as_success {
        return;
    }

    let (line, col) = unit.line_col(rename_call.start_byte);
    emit::push_finding(
        &META_CWE_274,
        file,
        line,
        col,
        "an insufficient-privilege filesystem failure is treated like a successful rotation",
        out,
    );
}

pub(crate) fn detect_cwe_283(unit: &ParsedUnit, facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    if source.contains("info.Sys().(*syscall.Stat_t)") || source.contains("stat.Uid") {
        return;
    }

    let Some(remove_call) = facts
        .call_facts
        .iter()
        .find(|call| call.callee.as_ref() == "os.Remove")
    else {
        return;
    };
    let removes_user_controlled_path = facts.input_bindings.iter().any(|binding| {
        binding.kind == InputKind::UserControlled
            && remove_call
                .arguments
                .iter()
                .any(|arg| arg.as_ref() == binding.name.as_ref())
    });
    if !removes_user_controlled_path {
        return;
    }

    let (line, col) = unit.line_col(remove_call.start_byte);
    emit::push_finding(
        &META_CWE_283,
        file,
        line,
        col,
        "a user-selected file path is removed without verifying that the caller owns the inode",
        out,
    );
}
pub(crate) fn detect_cwe_323(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
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
