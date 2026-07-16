CARGO ?= cargo
SCAN_PATH ?= /home/chinmay/ChinmayPersonalProjects/gopdfsuit
RUN_ARGS ?=
# Optional: SKIP_BUILD=1 runs the existing release binary with no cargo work.
# Example: make run SKIP_BUILD=1 RUN_ARGS="--export-context --export-chunks"
SKIP_BUILD ?= 0

RELEASE_BIN := ./target/release/codehound

# Build the project
build:
	$(CARGO) build

# Run project tests
test:
	$(CARGO) test

# Check code for linting issues using clippy
lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	$(CARGO) fmt --check

# Apply code formatting
fmt:
	$(CARGO) fmt

# Local full-catalog scan (summary only). CLI default pack is `recommended`;
# use RUN_ARGS='--profile recommended' for the CI pack. Override SCAN_PATH as needed.
#   make run RUN_ARGS="--export-context --export-chunks"
#   make run SKIP_BUILD=1   # no recompile; requires target/release/codehound already built
#
# Uses the release binary for real timings. `cargo build --release` is nearly free
# when sources are unchanged; dirty LTO rebuilds can take a few minutes.
run:
	@if [ "$(SKIP_BUILD)" = "1" ]; then \
		test -x $(RELEASE_BIN) || { echo "missing $(RELEASE_BIN); run: make run  (or cargo build --release)"; exit 1; }; \
		echo ">>> SKIP_BUILD=1: running existing $(RELEASE_BIN)"; \
	else \
		echo ">>> ensuring release binary is up to date (skips compile if nothing changed)..."; \
		$(CARGO) build --release; \
	fi
	@$(RELEASE_BIN) $(SCAN_PATH) --no-fail --no-terminal --profile all $(RUN_ARGS)

# Enhanced PERF set (1:1 plan themes) — prints findings so they are not buried by BP/CWE.
PERF_ENHANCED_ONLY ?= PERF-018,PERF-027,PERF-032,PERF-054,PERF-109,PERF-192,PERF-215,PERF-217,PERF-218,PERF-219,PERF-221,PERF-225,PERF-226,PERF-227,PERF-228,PERF-229,PERF-230,PERF-231,PERF-232,PERF-233,PERF-234,PERF-235,PERF-236,PERF-237,PERF-238,PERF-239,PERF-240,PERF-241,PERF-242
run-perf-enhanced:
	@$(CARGO) build --release
	@$(RELEASE_BIN) $(SCAN_PATH) --no-fail --format text --no-context --no-chunks --only $(PERF_ENHANCED_ONLY) $(RUN_ARGS)

run-sarif:
	@$(CARGO) build --release
	@$(RELEASE_BIN) $(SCAN_PATH) --no-fail --format sarif ./... > out.sarif

# Run benchmarks. Set SAVE_BASELINE=1 to save a new baseline.
bench:
	$(CARGO) bench
bench-save:
	$(CARGO) bench -- --save-baseline main

# Generate a CHANGELOG entry stub.
changelog:
	@echo "## [unreleased] - $$(date +%Y-%m-%d)" && echo "" && echo "### Added" && echo "" && echo "### Changed" && echo "" && echo "### Fixed" && echo ""
