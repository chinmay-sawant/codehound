# PERF Detector Development Guide

> How to add, test, and maintain Go performance heuristic rules.

## Architecture Overview

```
ruleset/golang/golang.json  ──→  build.rs  ──→  go_perf_metadata.rs (generated)
                                    │
src/lang/go/detectors/perf/         │
  registry/*.toml        ────────→  │  ──→  go_perf_registry.rs (generated)
  dispatch.rs            ←──────────┘
  domains/*.rs           ←── implements detect_perf_NNN
  facts.rs               ←── GoPerfFacts + PerfSourceIndex pre-filter
```

Each PERF rule has three things:

1. **JSON metadata entry** in `ruleset/golang/golang.json` (id, name, description, severity, etc.)
2. **Registry TOML entry** in `src/lang/go/detectors/perf/registry/registry.{domain}.toml` (wires rule → implementation)
3. **Detector function** in `src/lang/go/detectors/perf/domains/{domain}.rs` (the actual detection logic)

`build.rs` reads both sources and generates:
- `go_perf_metadata.rs` — `META_PERF_N` constants from `golang.json`
- `go_perf_registry.rs` — dispatch table mapping perf IDs to `detect_perf_N` function pointers

## Adding a New PERF Rule

### Step 1: Add JSON metadata

Add an entry to the appropriate section in `ruleset/golang/golang.json`:

```json
{
  "id": 213,
  "name": "Unnecessary string conversion in hot path",
  "description": "Detects unnecessary string([]byte) conversions inside request handlers.",
  "original_description": "Found repeated string conversion from []byte in loop.",
  "category": "performance",
  "applicable_to": "go",
  "go_relevance": "high",
  "detection_notes": "Look for string(byteSlice) inside for loops within handler-scope functions."
}
```

### Step 2: Add registry TOML entry

Pick the matching domain module and add to its `registry.{domain}.toml`:

```toml
[[rule]]
perf = 213
domain = "string_bytes"
function = "detect_perf_213"
```

**Existing domains:**

| TOML file | Rust module | Example rules |
|-----------|------------|--------------|
| `registry.concurrency.toml` | `domains/concurrency.rs` | PERF-148, 167, 172, 173, 174, 175, 183, 193, 194 |
| `registry.data_access.toml` | `domains/data_access/` | PERF-160, 162, 164, 205, 206 |
| `registry.general_perf.toml` | `domains/general_perf/` | PERF-101..141 (category A/B mix) |
| `registry.gin_framework.toml` | `domains/gin_framework/` | Gin-specific patterns |
| `registry.loop_allocations.toml` | `domains/loop_allocations/` | PERF-108, 109 |
| `registry.parsing_in_loops.toml` | `domains/parsing_in_loops/` | PERF-180, 186 |
| `registry.protocols.toml` | `domains/protocols/` | HTTP protocol patterns |
| `registry.request_path.toml` | `domains/request_path/` | PERF-141, 144 |
| `registry.memory_gc.toml` | `domains/memory_gc.rs` | PERF-134, 138, 139, 150, 151, 169, 191 |
| `registry.stdlib_optimization.toml` | `domains/stdlib_optimization.rs` | PERF-142, 143, 152, 153, 154, 155, 159, 160, 162, 164, 180, 184, 185, 187, 188, 189, 196, 197, 199, 200, 201, 202, 205, 206, 207, 210, 212 |
| `registry.string_bytes.toml` | `domains/string_bytes.rs` | PERF-159, 178, 179, 186, 203 |

Don't see a matching domain? Add a new file to both `registry/` and `domains/`, then wire it in `build.rs`.

### Step 3: Implement the detector function

Create `detect_perf_213` in the appropriate domain module:

```rust
use crate::core::ParsedUnit;
use crate::lang::go::detectors::perf::facts::GoPerfFacts;
use crate::lang::go::detectors::perf::metadata::META_PERF_213;
use crate::rules::{emit, Finding};

pub(crate) fn detect_perf_213(
    unit: &ParsedUnit,
    facts: &GoPerfFacts,
    out: &mut Vec<Finding>,
) {
    // Check if file has a handler-shaped function (fast pre-filter).
    if !facts.source_index.has("string(") {
        return;
    }

    let source = unit.source.as_ref();

    // Walk all call expressions looking for the pattern.
    for call in &facts.call_facts {
        if call.callee.as_ref().contains("string(") && is_in_handler(call, unit) {
            let (line, col) = unit.line_col(call.start_byte);
            emit::push_finding_with_evidence(
                &META_PERF_213,
                unit.display_path.as_str(),
                line,
                col,
                "unnecessary string([]byte) conversion in hot path",
                crate::rules::DetectorEvidence::DangerousCall {
                    function: call.callee.to_string(),
                    argument_index: None,
                },
                out,
            );
        }
    }
}
```

**Signature requirements:**

- Takes `&ParsedUnit`, `&GoPerfFacts`, `&mut Vec<Finding>`
- Returns `()` (findings are pushed into `out`)
- Uses `facts.source_index.has(...)` for fast pre-filtering

### Step 4: Regenerate dispatch code

```bash
cargo build
```

`build.rs` reads all `registry.*.toml` files and `golang.json`, then:
1. Generates `META_PERF_213` from the JSON metadata
2. Wires `PERF-213 → detect_perf_213` in the dispatch table
3. Both generated files land in `$OUT_DIR` and are `include!`-ed

## Fixture Creation

Every PERF rule needs a vulnerable/safe fixture pair:

```bash
tests/fixtures/go/perf/PERF-213-vulnerable.txt
tests/fixtures/go/perf/PERF-213-safe.txt
```

### Fixture format

Each `.txt` fixture embeds Go source that `tests/helpers/mod.rs::assert_fixture_materializes()` converts to a `.go` file:

```
# PERF-213 positive: string([]byte) conversion in handler loop
lang: go
file: PERF-213-vulnerable.go
variant: stdlib
---
package sample

import "net/http"

func ServePage(w http.ResponseWriter, r *http.Request) {
    data := []byte("hello")
    for i := 0; i < 10; i++ {
        _ = string(data)  // vulnerable: hot-path conversion
    }
    w.WriteHeader(200)
}
```

**Rules:**
- First line is a `#` comment describing the test case
- `lang: go` — language identifier
- `file: <name>.go` — output filename after materialization
- `variant: stdlib | framework | pure-go` — optional, for fixture categorization
- `---` separator on its own line
- Go source follows the separator

**Naming convention:** `{rule_id}-{vulnerable|safe}.txt` — e.g. `PERF-213-vulnerable.txt`

### Register in manifest.toml

Add both files to `tests/fixtures/manifest.toml`:

```toml
[[fixture]]
lang = "go"
path = "tests/fixtures/go/perf/PERF-213-vulnerable.txt"
required_rules = ["PERF-213"]

[[fixture]]
lang = "go"
path = "tests/fixtures/go/perf/PERF-213-safe.txt"
required_rules = []
```

### Testing

```bash
# Run all PERF fixture tests
cargo test --test go_perf_detector_integration

# Run a specific rule
cargo test --test go_perf_detector_integration -- perf_213

# Verify registry generation
cargo test --test go_perf_registry_generation

# Run smoke budget test
cargo test --test perf_regression
```

## Pre-filtering with `PerfSourceIndex`

Every PERF detector should use `facts.source_index.has(...)` as a fast pre-filter:

```rust
// Before doing any real work, check for a needle in the source.
if !facts.source_index.has("string(") {
    return;  // can't possibly match
}
```

The `SourceIndex` is built once per file during `collect_entries()` and contains all string literals, identifiers, and call patterns. The `has()` check is a substring scan over the precomputed index — O(keys) not O(source).

Add new needles to `src/lang/go/detectors/perf/facts.rs` in `GoPerfFacts::new()` if your rule looks for a pattern not already indexed.

## Domain Module Layout

```
src/lang/go/detectors/perf/
├── mod.rs                  # Re-exports, dispatcher
├── dispatch.rs             # Generated dispatch table (include! from OUT_DIR)
├── facts.rs                # GoPerfFacts + PerfSourceIndex
├── common.rs               # Shared helpers: is_handler_shaped, file_has_handler
├── metadata.rs             # Generated META_PERF_N constants (include! from OUT_DIR)
├── registry/
│   ├── registry.concurrency.toml
│   ├── registry.data_access.toml
│   ├── registry.general_perf.toml
│   ├── registry.gin_framework.toml
│   ├── registry.loop_allocations.toml
│   ├── registry.memory_gc.toml
│   ├── registry.parsing_in_loops.toml
│   ├── registry.protocols.toml
│   ├── registry.request_path.toml
│   ├── registry.stdlib_optimization.toml
│   └── registry.string_bytes.toml
└── domains/
    ├── mod.rs              # Re-exports submodules
    ├── concurrency.rs
    ├── memory_gc.rs
    ├── string_bytes.rs
    ├── stdlib_optimization.rs
    ├── general_perf/
    ├── data_access/
    ├── gin_framework/
    ├── loop_allocations/
    ├── parsing_in_loops/
    ├── protocols/
    └── request_path/
```

### When to create a new domain module

If the new rule doesn't fit any existing domain:
1. Create the implementation file in `domains/`
2. Create a matching `registry/registry.{name}.toml`
3. Add a `pub(crate) use` re-export in `domains/mod.rs`
4. Update `build.rs` to include the new registry file

## Developer Workflow Summary

```bash
# 1. Edit golang.json for metadata (if new rule id)
# 2. Add registry entry in registry/{domain}.toml
# 3. Implement detector in domains/{domain}.rs
# 4. Create fixture pair in tests/fixtures/go/perf/
# 5. Register fixture in tests/fixtures/manifest.toml
# 6. cargo build          # regenerate dispatch + metadata
# 7. cargo test --test go_perf_detector_integration  # verify fixture passes
# 8. cargo clippy         # no warnings
# 9. cargo fmt            # formatting
```
