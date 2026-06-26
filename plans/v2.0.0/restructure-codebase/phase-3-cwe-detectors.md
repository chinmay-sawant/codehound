# Phase 3 — CWE Detectors

> **Parent:** `README.md` (master plan, v2.0.0)
> **Status:** Not started. All sections are planning only — no source files have been moved yet.
> **Estimated effort:** 1-1.5 weeks. ~75 new files. The most error-prone phase — `..` path corrections and `pub use` re-exports must be done carefully.

---

## Overview

Split every oversized file under `src/lang/go/detectors/cwe/metadata_overrides.rs`, `src/lang/go/detectors/cwe/taint/*` (overlap with Phase 1), `src/lang/go/detectors/cwe/facts.rs` (overlap with Phase 1), `src/lang/go/detectors/bad_practices/*`, and `src/lang/go/detectors/cwe/domains/*`.

**Scope:** `src/lang/go/detectors/cwe/metadata_overrides.rs`, `src/lang/go/detectors/cwe/taint/*` (overlaps with Phase 1), `src/lang/go/detectors/cwe/facts.rs` (overlaps with Phase 1), `src/lang/go/detectors/bad_practices/*`, `src/lang/go/detectors/cwe/domains/*`.
**Files covered:** 30 (28 require splitting).
**New files:** ~75.

---

## Executive Summary

- **Problem:** `metadata_overrides.rs` (28 371 chars / 587 lines) holds 144 `severity_for` arms + 99+ `fix_for` arms in a single file. The domain cluster files range from 3 046 to 14 611 chars.
- **Approach:** Convert each flat detector file into a folder of focused sub-modules. Every new `mod.rs` is private; public surface is re-exported with `pub use`. Preserve the `cwe::domains::<domain>::<cluster>::detect_cwe_22` → … → `cwe::detect_cwe_22` reachability chain.
- **Success criteria:** All 30 files in scope are either split or confirmed. Every `pub(crate) fn detect_cwe_NNN` name and signature byte-identical. `META_CWE_NNN: RuleMetadata` constants still callable in `const` context. The canary test `tests/go_cwe_detector_integration.rs` is green.
- **Trade-offs:** `metadata_overrides.rs` is best kept flat with comments (Option A). Domain files become folders with 2–3 sub-files each.
- **Open questions:** Should `metadata_overrides.rs` be split by id-range (Option B) or kept flat (Option A)? **Recommendation: Option A.**

---

## Phase 3.0: Critical design rules (apply to every section below)

- [ ] **Detector function names are sacred.** Every `pub(crate) fn detect_cwe_NNN(...)` and every metadata constant `pub(super) const META_CWE_NNN: RuleMetadata` must keep its name and signature byte-identical. The build script (`build.rs:248-256`, `build.rs:113-117`) emits `("CWE-NNN", detect_cwe_NNN, &META_CWE_NNN)` tuples into `OUT_DIR/go_cwe_registry.rs`; a renamed function silently breaks the build.
- [ ] **The `registry.toml` mapping is by function name only.** The `domain = "X"` field in `cwe/registry.toml` is `#[allow(dead_code)]` in `build.rs` — it is never validated against the file structure. The split is **invisible to the build**: no TOML changes are required, regardless of where the file lives on disk.
- [ ] **Reachability chain today:** `cwe::domains::<domain>::<cluster>::detect_cwe_22` → `cwe::domains::<domain>::detect_cwe_22` (via `pub(crate) use` in the domain's `mod.rs`) → `cwe::domains::detect_cwe_22` (via `pub(crate) use` in `domains/mod.rs`) → `cwe::detect_cwe_22` (via `use domains::*;` in `cwe/mod.rs:13`).
  - [ ] After the split, every new sub-`mod.rs` adds a `pub use` (or `pub(crate) use`) re-export so the chain length grows by one but the name is still reachable at `cwe::detect_cwe_22`.
- [ ] **Path depth correction:** when a flat detector file (`cwe/domains/injection.rs`) becomes a folder (`cwe/domains/injection/mod.rs` + sub-files), the `use super::super::…` paths inside the moved code become `use super::super::super::…` (one more `..` up). This applies to:
  - [ ] `super::super::super::facts::GoUnitFacts`
  - [ ] `super::super::super::metadata::*`
  - [ ] `super::super::common::*` (in injection, path_traversal, configuration, input_validation)
  - [ ] `super::super::taint::detect_cwe_*_taint` (in injection, input_validation, path_traversal)
- [ ] **`metadata_overrides::severity_for` and `fix_for` are `const fn`.** The generated `pub const META_CWE_NNN: RuleMetadata = emit::rule_meta(... severity_for(NNN) ...)` in `OUT_DIR/go_cwe_metadata.rs` calls them in `const` context. Any fan-out in the new `mod.rs` must be a `const`-expression match.
- [ ] **`metadata.rs` uses `include!("metadata_overrides.rs")` today.** If `metadata_overrides.rs` is converted from a flat `include!`'d file to a real `mod`, the directive becomes `pub(super) mod metadata_overrides;` and the file becomes `metadata_overrides/mod.rs`.

---

## Phase 3.1: `src/lang/go/detectors/cwe/metadata_overrides.rs` → `metadata_overrides/`

**Current size:** 28 371 chars / 587 lines.
**Top-level items:** `pub const fn severity_for(id: u32) -> Severity` (180 lines, 144 arms) + `pub const fn fix_for(id: u32) -> Option<&'static str>` (405 lines, 99+ arms).

### Option A — keep as a single file with comments (recommended)

- [ ] Add a short `// CWE-NNN: <topic>` header above each `Some(…)` arm.
- [ ] File stays flat. No `include!` change.

### Option B — split by CWE id range

- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/mod.rs` with `pub const fn severity_for` fan-out + `pub const fn fix_for` fan-out (~300 chars)
- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/severity_15_199.rs` — `severity_for` for ids 15..=199 (~600 chars)
- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/severity_200_599.rs` — ids 200..=599 (~600 chars)
- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/severity_600_1392.rs` — ids 600..=1392 (~600 chars)
- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/fix_15_199.rs` — `fix_for` for 15..=199 (~3 500 chars)
- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/fix_200_399.rs` — ids 200..=399 (~3 500 chars)
- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/fix_400_599.rs` — ids 400..=599 (~3 500 chars)
- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/fix_600_999.rs` — ids 600..=999 (~3 500 chars)
- [ ] Create `src/lang/go/detectors/cwe/metadata_overrides/fix_1000_1392.rs` — ids 1000..=1392 (~3 500 chars)
- [ ] Each `fix_NNN_MMM.rs` exports `pub(super) const fn fix_for(id: u32) -> Option<&'static str>` that returns `None` for ids outside its range. The fan-out in `mod.rs` is a `const`-compatible `match`.
- [ ] In `metadata.rs`, change `include!("metadata_overrides.rs")` → `pub(super) mod metadata_overrides;` (textual include becomes a real module).

### Caveat

- [ ] All `pub(super) const fn fix_for` must stay const.

### Recommendation

- [ ] **Option A** if the goal is to preserve the `include!` flow. **Option B** if the 30k char cap is strict.

---

## Phase 3.2: `src/lang/go/detectors/bad_practices/rules.rs` → `bad_practices/rules/`

**Current size:** 15 790 chars / 454 lines.
**Top-level items:** `push_at`, `line_start_byte`, 13 `detect_bp_*` detectors.

### Proposed file tree

- [ ] Create `src/lang/go/detectors/bad_practices/rules/mod.rs` with `mod` decls + `pub use error_handling::*; pub use panics::*; pub use sync::*; pub use loops::*;` (~50 chars)
- [ ] Create `src/lang/go/detectors/bad_practices/rules/helpers.rs` with `push_at` + `line_start_byte` (~700 chars)
- [ ] Create `src/lang/go/detectors/bad_practices/rules/error_handling.rs` with BP-1, BP-2, BP-4, BP-5 (~3 300 chars)
- [ ] Create `src/lang/go/detectors/bad_practices/rules/panics.rs` with BP-3, BP-13, BP-15 (~3 500 chars)
- [ ] Create `src/lang/go/detectors/bad_practices/rules/sync.rs` with BP-6, BP-7, BP-8, BP-9 (~3 500 chars)
- [ ] Create `src/lang/go/detectors/bad_practices/rules/loops.rs` with BP-10, BP-11 (~2 500 chars)
- [ ] Delete `src/lang/go/detectors/bad_practices/rules.rs`

### Compatibility notes

- [ ] Every `detect_bp_NN` references `crate::lang::go::detectors::bad_practices::BP_NN_META`. The metadata constants stay in `bad_practices/mod.rs` (see §3.3), so the absolute path is preserved.

---

## Phase 3.3: `src/lang/go/detectors/bad_practices/mod.rs` → `bad_practices/` + `metadata/`

**Current size:** 6 932 chars / 207 lines.
**Top-level items:** 13 `BP_*_META` consts, `BAD_PRACTICE_RULES`, `RULE_IDS`, `SCAN_METADATA`, `GoBadPracticeScan` struct + `Rule` + `Detector` impls.

### Proposed file tree

- [ ] Create `src/lang/go/detectors/bad_practices/mod.rs` (slim) with `mod metadata; mod dispatch; mod rules; use metadata::*; use rules::*;` + `pub struct GoBadPracticeScan` + the 2 impls (~70 lines)
- [ ] Create `src/lang/go/detectors/bad_practices/metadata.rs` with 13 `BP_*_META` consts + `SCAN_METADATA` (~4 500 chars)
- [ ] (Optional) Create `src/lang/go/detectors/bad_practices/metadata_error.rs` — BP-1, BP-2, BP-4, BP-5, BP-13 metadata (~2 000 chars)
- [ ] (Optional) Create `src/lang/go/detectors/bad_practices/metadata_locks.rs` — BP-6, BP-7, BP-8 (~1 500 chars)
- [ ] (Optional) Create `src/lang/go/detectors/bad_practices/metadata_loops.rs` — BP-9, BP-10, BP-11 (~1 500 chars)
- [ ] (Optional) Create `src/lang/go/detectors/bad_practices/metadata_panics.rs` — BP-3, BP-15 (~1 000 chars)
- [ ] Create `src/lang/go/detectors/bad_practices/dispatch.rs` with `BAD_PRACTICE_RULES` + `RULE_IDS` (~1 000 chars)
- [ ] Delete the old `src/lang/go/detectors/bad_practices/mod.rs` (replaced by the folder)

### `mod.rs` changes

- [ ] The current `mod rules; use rules::*;` block stays.
- [ ] The metadata constants move to `metadata.rs` and are re-exported with `pub(crate) use metadata::*;` so the absolute path `crate::lang::go::detectors::bad_practices::BP_*_META` (used by `rules.rs`) still resolves.

---

## Phase 3.4: `cwe/domains/access_control/auth_and_validation.rs` (14 611 chars / 466 lines, 16 detectors)

**Clusters:** Auth flows (login / session / MFA / password): 289, 290, 305, 306, 307, 308, 309, 620, 836. Auth tokens / challenges: 294, 301, 303, 322, 408. Cookies / session state: 603, 613.

### Proposed file tree (under `auth_and_validation/`)

- [ ] Create `auth_and_validation/mod.rs` with `mod` decls + `pub use auth_flows::*; pub use auth_tokens::*; pub use cookies::*;` (~25 chars)
- [ ] Create `auth_and_validation/auth_flows.rs` with 289, 290, 305, 306, 307, 308, 309, 620, 836 (~4 200 chars)
- [ ] Create `auth_and_validation/auth_tokens.rs` with 294, 301, 303, 322, 408 (~3 000 chars)
- [ ] Create `auth_and_validation/cookies.rs` with 603, 613 (~2 000 chars)
- [ ] Delete `auth_and_validation.rs`

### Optional further split of `auth_flows.rs`

- [ ] `auth_flows_login.rs` (289, 290)
- [ ] `auth_flows_bruteforce.rs` (305–309)
- [ ] `auth_flows_password.rs` (620, 836)

---

## Phase 3.5: `cwe/domains/general_security/identity_and_authentication.rs` (10 841 chars / 346 lines, 13 detectors)

**Clusters:** Constant-time / response-uniformity: 204, 208, 385. JWT structure: 358. Identity binding / policy: 454, 488, 565, 645, 649, 654, 656. MFA / defaults: 841, 842.

### Proposed file tree

- [ ] Create `identity_and_authentication/mod.rs` with `mod` decls + re-exports (~15 chars)
- [ ] Create `identity_and_authentication/crypto_comparison.rs` with 204, 208, 385 (~3 000 chars)
- [ ] Create `identity_and_authentication/jwt.rs` with 358 (~1 000 chars)
- [ ] Create `identity_and_authentication/policy.rs` with 454, 488, 565, 645, 649, 654, 656 (~4 500 chars)
- [ ] Create `identity_and_authentication/defaults.rs` with 841, 842 (~1 700 chars)
- [ ] Delete `identity_and_authentication.rs`

---

## Phase 3.6: `cwe/domains/injection.rs` (9 569 chars / 301 lines, 7 detectors)

**Clusters:** command/SQL/LDAP/XML (78, 89, 90, 91), header (93), resource (619, 917).

### Proposed file tree

- [ ] Create `injection/mod.rs` with re-exports (~12 chars)
- [ ] Create `injection/sinks.rs` with 78, 89, 90, 91 (~3 500 chars)
- [ ] Create `injection/header.rs` with 93 (~1 800 chars)
- [ ] Create `injection/resource.rs` with 619, 917 (~1 400 chars)
- [ ] Delete `injection.rs`

### Path correction

- [ ] `injection/sinks.rs` imports `super::super::taint::detect_cwe_78_taint` and `super::super::taint::detect_cwe_89_taint` (current paths). After the split, those become `super::super::super::taint::…` (one more `..`).

---

## Phase 3.7: `cwe/domains/general_security/input_and_parsing.rs` (9 700 chars / 326 lines, 9 detectors)

**Clusters:** normalization (178, 179, 182, 184), XML/DOCTYPE (112, 611), encoding/parse-quirks (838, 1286, 1389).

### Proposed file tree

- [ ] Create `input_and_parsing/mod.rs` with re-exports (~13 chars)
- [ ] Create `input_and_parsing/normalization.rs` with 178, 179, 182, 184 (~3 200 chars)
- [ ] Create `input_and_parsing/xml.rs` with 112, 611 (~2 500 chars)
- [ ] Create `input_and_parsing/parse_quirks.rs` with 838, 1286, 1389 (~3 200 chars)
- [ ] Delete `input_and_parsing.rs`

---

## Phase 3.8: `cwe/domains/general_security/privilege_escalation.rs` (8 845 chars / 285 lines, 8 detectors)

**Clusters:** role/scope (266, 267, 268), privilege transitions (270, 272, 273, 274, 1265).

### Proposed file tree

- [ ] Create `privilege_escalation/mod.rs` with re-exports (~12 chars)
- [ ] Create `privilege_escalation/role_scope.rs` with 266, 267, 268 (~2 500 chars)
- [ ] Create `privilege_escalation/transitions.rs` with 270, 272, 273, 274, 1265 (~5 400 chars)
- [ ] Delete `privilege_escalation.rs`

### Optional further split of `transitions.rs`

- [ ] `transitions_context.rs` (270–274) + `transitions_locks.rs` (1265)

---

## Phase 3.9: `cwe/domains/general_security/lifecycle_and_integrity.rs` (8 813 chars / 284 lines, 10 detectors)

**Clusters:** runtime state, plugins, lifecycle.

### Proposed file tree

- [ ] Create `lifecycle_and_integrity/mod.rs` with re-exports (~12 chars)
- [ ] Create `lifecycle_and_integrity/runtime_state.rs` with half (~2 800 chars)
- [ ] Create `lifecycle_and_integrity/plugins.rs` with quarter (~2 800 chars)
- [ ] Create `lifecycle_and_integrity/lifecycle.rs` with quarter (~2 800 chars)
- [ ] Delete `lifecycle_and_integrity.rs`

---

## Phase 3.10: `cwe/domains/general_security/crypto_and_integrity.rs` (8 780 chars)

### Proposed file tree

- [ ] Create `crypto_and_integrity/mod.rs` with re-exports (~12 chars)
- [ ] Create `crypto_and_integrity/crypto_strength.rs` with half (~2 900 chars)
- [ ] Create `crypto_and_integrity/cors_and_body.rs` with third (~2 900 chars)
- [ ] Create `crypto_and_integrity/destructive.rs` with sixth (~2 900 chars)
- [ ] Delete `crypto_and_integrity.rs`

---

## Phase 3.11: `cwe/domains/access_control/file_permissions.rs` (7 488 chars / 253 lines, 9 detectors)

**Clusters:** file modes (276, 277, 278, 279, 281, 921), temp/shared dirs (378, 379), fallthrough (280).

### Proposed file tree

- [ ] Create `file_permissions/mod.rs` with re-exports (~15 chars)
- [ ] Create `file_permissions/file_modes.rs` with 276, 277, 278, 279, 281, 921 (~4 500 chars)
- [ ] Create `file_permissions/temp_dirs.rs` with 378, 379 (~1 700 chars)
- [ ] Create `file_permissions/fallthrough.rs` with 280 (~1 000 chars)
- [ ] Delete `file_permissions.rs`

---

## Phase 3.12: `cwe/domains/cryptography.rs` (7 411 chars / 235 lines, 9 detectors)

**Clusters:** ciphers (325, 1204, 1240), PRNG (334, 335, 338, 342, 343), JWT (347).

### Proposed file tree

- [ ] Create `cryptography/mod.rs` with re-exports (~12 chars)
- [ ] Create `cryptography/ciphers.rs` with 325, 1204, 1240 (~2 500 chars)
- [ ] Create `cryptography/prng.rs` with 334, 335, 338, 342, 343 (~3 300 chars)
- [ ] Create `cryptography/jwt.rs` with 347 (~1 000 chars)
- [ ] Delete `cryptography.rs`

---

## Phase 3.13: `cwe/domains/credentials_and_secrets/credential_lifecycle.rs` (7 198 chars / 237 lines, 8 detectors)

**Clusters:** password aging (262, 263), key expiration (324), plaintext credentials (523, 547, 798), reset/recovery (549, 640).

### Proposed file tree

- [ ] Create `credential_lifecycle/mod.rs` with re-exports (~17 chars)
- [ ] Create `credential_lifecycle/password_aging.rs` with 262, 263 (~1 600 chars)
- [ ] Create `credential_lifecycle/key_expiration.rs` with 324 (~1 400 chars)
- [ ] Create `credential_lifecycle/credentials_in_source.rs` with 523, 547, 798 (~2 600 chars)
- [ ] Create `credential_lifecycle/reset_recovery.rs` with 549, 640 (~2 000 chars)
- [ ] Delete `credential_lifecycle.rs`

---

## Phase 3.14: `cwe/domains/general_security/environment_exposure.rs` (7 519 chars)

### Proposed file tree

- [ ] Create `environment_exposure/mod.rs` with re-exports
- [ ] Create `environment_exposure/network.rs` (~2 500 chars)
- [ ] Create `environment_exposure/filesystem.rs` (~2 500 chars)
- [ ] Create `environment_exposure/diagnostics.rs` (~2 500 chars)
- [ ] Delete `environment_exposure.rs`

---

## Phase 3.15: `cwe/domains/general_security/path_and_file.rs` (5 901 chars)

### Proposed file tree

- [ ] Create `path_and_file/mod.rs` with re-exports
- [ ] Create `path_and_file/path_validation.rs` (~3 000 chars)
- [ ] Create `path_and_file/file_locks.rs` (~2 500 chars)
- [ ] Delete `path_and_file.rs`

---

## Phase 3.16: `cwe/domains/input_validation.rs` (5 878 chars / 197 lines, 5 detectors)

**Clusters:** output encoding (76, 79), CSV/payload (140, 1173, 1236).

### Proposed file tree

- [ ] Create `input_validation/mod.rs` with re-exports (~12 chars)
- [ ] Create `input_validation/output_encoding.rs` with 76, 79 (~2 300 chars)
- [ ] Create `input_validation/payloads.rs` with 140, 1173, 1236 (~2 500 chars)
- [ ] Delete `input_validation.rs`

### Path correction

- [ ] `output_encoding.rs` imports `super::super::taint::detect_cwe_79_taint` (current path). After the split → `super::super::super::taint::…`.

---

## Phase 3.17: `cwe/domains/information_exposure/secrets_and_transport.rs` (6 119 chars / 196 lines, 6 detectors)

**Clusters:** payloads (212, 214, 312), transport (319, 524, 538).

### Proposed file tree

- [ ] Create `secrets_and_transport/mod.rs` with re-exports (~12 chars)
- [ ] Create `secrets_and_transport/payloads.rs` with 212, 214, 312 (~2 700 chars)
- [ ] Create `secrets_and_transport/transport.rs` with 319, 524, 538 (~3 200 chars)
- [ ] Delete `secrets_and_transport.rs`

---

## Phase 3.18: `cwe/domains/information_exposure/response_leaks.rs` (5 696 chars / 184 lines, 6 detectors)

**Clusters:** sensitive fields (201, 213), metadata leaks (209, 215, 756, 1230).

### Proposed file tree

- [ ] Create `response_leaks/mod.rs` with re-exports (~12 chars)
- [ ] Create `response_leaks/sensitive_fields.rs` with 201, 213 (~2 000 chars)
- [ ] Create `response_leaks/metadata_leaks.rs` with 209, 215, 756, 1230 (~3 200 chars)
- [ ] Delete `response_leaks.rs`

---

## Phase 3.19: `cwe/domains/general_security/authorization_bypass.rs` (5 682 chars / 180 lines, 6 detectors)

**Clusters:** logic (783, 807, 909, 915), OAuth (940, 941).

### Proposed file tree

- [ ] Create `authorization_bypass/mod.rs` with re-exports (~12 chars)
- [ ] Create `authorization_bypass/logic.rs` with 783, 807, 909, 915 (~2 700 chars)
- [ ] Create `authorization_bypass/oauth.rs` with 940, 941 (~1 800 chars)
- [ ] Delete `authorization_bypass.rs`

---

## Phase 3.20: `cwe/domains/configuration.rs` (5 254 chars / 171 lines, 6 detectors)

**Clusters:** secrets in config (260, 455), config hardcoding (15, 472, 1051, 1067).

### Proposed file tree

- [ ] Create `configuration/mod.rs` with re-exports (~12 chars)
- [ ] Create `configuration/secrets_in_config.rs` with 260, 455 (~2 200 chars)
- [ ] Create `configuration/config_hardcoding.rs` with 15, 472, 1051, 1067 (~3 000 chars)
- [ ] Delete `configuration.rs`

### Path correction

- [ ] `secrets_in_config.rs` and `config_hardcoding.rs` import `super::super::common::*` (current path). After the split → `super::super::super::common::*` (one more `..`).

---

## Phase 3.21: `cwe/domains/concurrency.rs` (5 143 chars / 170 lines, 6 detectors)

**Clusters:** shared state (366, 368, 421, 820, 821), TOCTOU (367).

### Proposed file tree

- [ ] Create `concurrency/mod.rs` with re-exports (~12 chars)
- [ ] Create `concurrency/shared_state.rs` with 366, 368, 421, 820, 821 (~4 000 chars)
- [ ] Create `concurrency/toctou.rs` with 367 (~800 chars)
- [ ] Delete `concurrency.rs`

---

## Phase 3.22: `cwe/domains/access_control/authorization_and_scoping.rs` (4 676 chars / 152 lines, 5 detectors)

**Clusters:** authorization guards (425, 551, 653), owner scoping (639, 1220).

### Proposed file tree

- [ ] Create `authorization_and_scoping/mod.rs` with re-exports (~15 chars)
- [ ] Create `authorization_and_scoping/guards.rs` with 425, 551, 653 (~2 400 chars)
- [ ] Create `authorization_and_scoping/scoping.rs` with 639, 1220 (~2 200 chars)
- [ ] Delete `authorization_and_scoping.rs`

---

## Phase 3.23: `cwe/domains/general_security/permissions_and_ownership.rs` (4 474 chars / 144 lines, 5 detectors)

**Clusters:** file modes (250, 252, 552), chown (648, 708).

### Proposed file tree

- [ ] Create `permissions_and_ownership/mod.rs` with re-exports (~12 chars)
- [ ] Create `permissions_and_ownership/file_modes.rs` with 250, 252, 552 (~2 200 chars)
- [ ] Create `permissions_and_ownership/chown.rs` with 648, 708 (~1 800 chars)
- [ ] Delete `permissions_and_ownership.rs`

---

## Phase 3.24: `cwe/domains/credentials_and_secrets/password_storage.rs` (6 546 chars / 206 lines, 7 detectors)

**Clusters:** hashing (256, 257, 261, 916), policy (521), bootstrap (1052, 1392).

### Proposed file tree

- [ ] Create `password_storage/mod.rs` with re-exports (~14 chars)
- [ ] Create `password_storage/hashing.rs` with 256, 257, 261, 916 (~3 200 chars)
- [ ] Create `password_storage/policy.rs` with 521 (~1 000 chars)
- [ ] Create `password_storage/bootstrap.rs` with 1052, 1392 (~1 700 chars)
- [ ] Delete `password_storage.rs`

---

## Phase 3.25: `cwe/domains/deserialization.rs` (3 046 chars / 93 lines, 3 detectors) — optional

**Clusters:** trust mixing (349, 501), decoder choice (502).

### Proposed file tree

- [ ] Create `deserialization/mod.rs` with re-exports (~10 chars)
- [ ] Create `deserialization/trust_mixing.rs` with 349, 501 (~1 800 chars)
- [ ] Create `deserialization/decoders.rs` with 502 (~1 100 chars)
- [ ] Delete `deserialization.rs`

### Recommendation

- [ ] **Optional.** 3 046 chars is borderline. Skip unless the 3 000-char cap is strict.

---

## Phase 3.26: Cross-module reference inventory (after split)

- [ ] `cwe::common::*` — used by tests `lang_go_detectors_cwe_common.rs` (high)
- [ ] `cwe::facts::AssignmentFact` — used by tests `lang_go_detectors_cwe_common.rs`, `lang_go_detectors_cwe_facts.rs` (high)
- [ ] `cwe::facts::GoUnitFacts`, `InputKind`, etc. — used by tests, detectors (high)
- [ ] `cwe::source_index::SourceIndex` — used by tests, detectors (high)
- [ ] `cwe::GoCweScan` — used by tests `lang_go_cwe_metadata.rs` (high)
- [ ] `bad_practices::BP_*_META` constants — used by `bad_practices/rules.rs` (absolute path) (high)
- [ ] `bad_practices::GoBadPracticeScan` — used by `detectors/mod.rs:12` (high)

All of these are preserved by the re-exports in each new `mod.rs`.

---

## Phase 3.27: Tests / benchmarks — no updates required

After auditing, **no test or benchmark file needs editing** for any proposed split. The detector source files are not directly referenced by tests; tests use:

- [ ] `slopguard::lang::go::detectors::cwe::GoCweScan` (unchanged)
- [ ] `slopguard::lang::go::detectors::cwe::common::*` (unchanged)
- [ ] `slopguard::lang::go::detectors::cwe::facts::*` (unchanged)
- [ ] `slopguard::lang::go::detectors::cwe::source_index::SourceIndex` (unchanged)

The integration test `tests/go_cwe_detector_integration.rs` discovers fixtures by CWE id, runs every `CWE-N` detector, and asserts the registry is in sync. If a `pub use` is forgotten, this test reports a missing finding for the affected CWE — it is the **canary test** for the split.

---

## Phase 3.28: Recommended order of operations

- [ ] **Smallest leaves first** to validate the `pub use` re-export pattern: §3.25 (deserialization), §3.23 (permissions_and_ownership), §3.22 (authorization_and_scoping), §3.21 (concurrency), §3.20 (configuration), §3.19 (authorization_bypass).
- [ ] **Medium leaves:** §3.18, 3.17, 3.16, 3.24, 3.13, 3.12, 3.11, 3.14, 3.15, 3.10, 3.9, 3.8, 3.7.
- [ ] **Large leaves:** §3.5 (identity_and_authentication), §3.4 (auth_and_validation), §3.6 (injection).
- [ ] **`taint/*`:** §3.1 § metadata_overrides (last because of the const-fn fan-out); then §1.18–1.21 (taint mod.rs, extract, graph, rules) per Phase 1.
- [ ] **`bad_practices/*`:** §3.3 (mod.rs + metadata), then §3.2 (rules).
- [ ] **`cwe/facts.rs`:** §1.22.
- [ ] **Verification after each batch:** `cargo build --features go && cargo test --test go_cwe_detector_integration`

---

## Phase 3.29: Caveat about `..` paths (most error-prone)

When a single-file detector (`injection.rs`) becomes a directory with sub-files (`injection/sinks.rs`), the `use super::super::…` paths inside the moved code need **one more `..` up**. This applies to:

- [ ] `use super::super::super::facts::GoUnitFacts;` → `use super::super::super::super::facts::GoUnitFacts;` in the new deeper sub-files.
- [ ] `use super::super::super::metadata::*;` → similarly.
- [ ] `use super::super::common::*;` → `use super::super::super::common::*;` in the new deeper sub-files of `injection.rs`, `path_traversal.rs`, `configuration.rs`, `input_validation.rs`.
- [ ] `use super::super::taint::detect_cwe_*_taint;` → `use super::super::super::taint::detect_cwe_*_taint;` in the same set.

---

## Phase 3 verification

- [ ] After every batch: `cargo build --features go && cargo test --test go_cwe_detector_integration`
- [ ] Final, after all CWE detector splits: `cargo test --test go_cwe_detector_integration --test lang_go_cwe_metadata --test lang_go_detectors_cwe_common --test lang_go_detectors_cwe_facts`
- [ ] Cross-check that BP_*_META references still work: `cargo test --test go_perf_detector_integration`
- [ ] Canary: `tests/go_cwe_detector_integration.rs` discovers fixtures by CWE id and runs every CWE-N detector. If a `pub use` is forgotten, this test reports a missing finding for the affected CWE.

---

## Dependencies

- **Crate dependencies:** none added.
- **External tools:** none.
- **Cross-cutting concerns:**
  - **Detector name preservation is the #1 risk.** Every `pub(crate) fn detect_cwe_NNN` and every `pub(super) const META_CWE_NNN: RuleMetadata` must keep its name and signature byte-identical. The build script's function-pointer dispatch silently breaks if a name changes.
  - **The `..` path correction (§3.29) is the #2 risk.** When a flat detector file becomes a directory with sub-files, `use super::super::…` paths inside the moved code need one more `..` up. Forgetting this causes "cannot find type `GoUnitFacts`" build errors.
  - **Const-fn preservation** (`metadata_overrides::severity_for` / `fix_for` are `const fn`) is the #3 risk. The generated `pub const META_CWE_NNN` in `OUT_DIR/go_cwe_metadata.rs` calls them in const context. Any fan-out in the new `mod.rs` must be a `const`-expression match.
  - **No test changes** — the canary test catches every missing `pub use`. The 30 source-file splits in this phase produce ~75 new files but zero test edits.
  - **Phase 1 overlap** — `cwe/facts.rs` (§1.22) and `cwe/taint/*` (§1.18–1.21) are de-facto in-scope for both Phase 1 and Phase 3. Coordinate the order so Phase 1's splits land first.
