use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// PERF-51: `unsafe.Pointer` in a request handler without benchmark justification.
pub(crate) fn detect_perf_51(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("unsafe.Pointer") {
        return;
    }
    if source.contains("// benchmark justifies unsafe.Pointer")
        || source.contains("// nolint:unsafe-ptr")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_51,
        source.find("unsafe.Pointer").unwrap_or(0),
        "unsafe.Pointer is used in a request handler; prefer safe alternatives unless a benchmark justifies the pattern",
        out,
    );
}

/// PERF-52: `runtime.GC()` outside tests, debug builds, or shutdown paths.
pub(crate) fn detect_perf_57(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source)
        || (!source.contains("*gin.Context") && !source.contains("gin.HandlerFunc"))
    {
        return;
    }
    if !source.contains("c.Next()") {
        return;
    }
    let trig = ["io.ReadAll(", "json.Unmarshal("];
    if !trig.iter().any(|t| source.contains(t)) {
        return;
    }
    emit_at(
        unit,
        &META_PERF_57,
        first_pos(source, &trig),
        "heavy work in a Gin middleware (io.ReadAll / json.Unmarshal) runs for every request",
        out,
    );
}

/// PERF-62: complex `c.Param` parsing in middleware.
pub(crate) fn detect_perf_62(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("c.Param(") {
        return;
    }
    let has_parser = source.contains("regexp.MustCompile(")
        || source.contains("regexp.Compile(")
        || source.contains("json.Unmarshal(");
    if !has_parser {
        return;
    }
    emit_at(
        unit,
        &META_PERF_62,
        source.find("c.Param(").unwrap_or(0),
        "complex c.Param parsing (regex / json.Unmarshal) lives in middleware; move to the route handler that needs it",
        out,
    );
}

/// PERF-63: `binding.Validator.Engine()` invoked in a request handler.
pub(crate) fn detect_perf_63(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(source) || !source.contains("binding.Validator.Engine()") {
        return;
    }
    if source.contains("var engine = binding.Validator.Engine()")
        || source.contains("once.Do(func()")
        || source.contains("sync.Once")
    {
        return;
    }
    emit_at(
        unit,
        &META_PERF_63,
        source.find("binding.Validator.Engine()").unwrap_or(0),
        "binding.Validator.Engine() is invoked per request; cache the engine at startup",
        out,
    );
}

/// PERF-64: `go func()` using `*gin.Context` without `c.Copy()`.
pub(crate) fn detect_perf_65(unit: &ParsedUnit, _facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let middleware_registered = source.contains("r.Use(")
        || source.contains("RouterGroup.Use(")
        || source.contains("routerGroup.Use(")
        || source.contains("engine.Use(");
    if !middleware_registered || !source.contains("c.ShouldBind(") {
        return;
    }
    emit_at(
        unit,
        &META_PERF_65,
        source.find("c.ShouldBind(").unwrap_or(0),
        "c.ShouldBind runs in middleware registered via .Use(); it parses the body for every route in the chain",
        out,
    );
}
