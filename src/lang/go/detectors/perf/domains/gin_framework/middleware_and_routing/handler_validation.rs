use super::super::super::super::common::is_request_path;
use super::super::super::super::facts::GoPerfFacts;
use super::super::super::super::metadata::*;
use super::super::common::*;
use crate::core::ParsedUnit;
use crate::rules::Finding;

/// PERF-51: `unsafe.Pointer` in a request handler without benchmark justification.
pub(crate) fn detect_perf_51(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(&facts.source_index) || !facts.source_index.has("unsafe.Pointer") {
        return;
    }
    if facts
        .source_index
        .has("// benchmark justifies unsafe.Pointer")
        || facts.source_index.has("// nolint:unsafe-ptr")
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
pub(crate) fn detect_perf_57(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(&facts.source_index)
        || (!facts.source_index.has("*gin.Context") && !facts.source_index.has("gin.HandlerFunc"))
    {
        return;
    }
    if !facts.source_index.has("c.Next()") {
        return;
    }
    let trig = ["io.ReadAll(", "json.Unmarshal("];
    if !facts.source_index.has_any(&trig) {
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
pub(crate) fn detect_perf_62(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(&facts.source_index) || !facts.source_index.has("c.Param(") {
        return;
    }
    let has_parser = facts.source_index.has("regexp.MustCompile(")
        || facts.source_index.has("regexp.Compile(")
        || facts.source_index.has("json.Unmarshal(");
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
pub(crate) fn detect_perf_63(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    if !is_request_path(&facts.source_index)
        || !facts.source_index.has("binding.Validator.Engine()")
    {
        return;
    }
    if facts
        .source_index
        .has("var engine = binding.Validator.Engine()")
        || facts.source_index.has("once.Do(func()")
        || facts.source_index.has("sync.Once")
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
pub(crate) fn detect_perf_65(unit: &ParsedUnit, facts: &GoPerfFacts, out: &mut Vec<Finding>) {
    let source = unit.source.as_ref();
    let middleware_registered = facts.source_index.has("r.Use(")
        || facts.source_index.has("RouterGroup.Use(")
        || facts.source_index.has("routerGroup.Use(")
        || facts.source_index.has("engine.Use(");
    if !middleware_registered || !facts.source_index.has("c.ShouldBind(") {
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
