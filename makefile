CARGO ?= cargo
SCAN_PATH ?= /home/chinmay/ChinmayPersonalProjects/gopdfsuit
RUN_ARGS ?=

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

# Run codehound against a path. Override SCAN_PATH or RUN_ARGS as needed.
run:
	@$(CARGO) run --quiet -- $(SCAN_PATH) --no-fail --no-terminal $(RUN_ARGS)

# Enhanced PERF set (1:1 plan themes) — prints findings so they are not buried by BP/CWE.
PERF_ENHANCED_ONLY ?= PERF-018,PERF-027,PERF-032,PERF-054,PERF-109,PERF-192,PERF-215,PERF-217,PERF-218,PERF-219,PERF-221,PERF-225,PERF-226,PERF-227,PERF-228,PERF-229,PERF-230,PERF-231,PERF-232,PERF-233,PERF-234,PERF-235,PERF-236,PERF-237,PERF-238,PERF-239,PERF-240,PERF-241,PERF-242
run-perf-enhanced:
	@$(CARGO) run --quiet -- $(SCAN_PATH) --no-fail --format text --no-context --no-chunks --only $(PERF_ENHANCED_ONLY) $(RUN_ARGS)

run-sarif:
	@$(CARGO) run --quiet -- $(SCAN_PATH) --no-fail --format sarif ./... > out.sarif

# Run benchmarks. Set SAVE_BASELINE=1 to save a new baseline.
bench:
	$(CARGO) bench
bench-save:
	$(CARGO) bench -- --save-baseline main

# Generate a CHANGELOG entry stub.
changelog:
	@echo "## [unreleased] - $$(date +%Y-%m-%d)" && echo "" && echo "### Added" && echo "" && echo "### Changed" && echo "" && echo "### Fixed" && echo ""
