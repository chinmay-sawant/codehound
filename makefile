CARGO ?= cargo
SCAN_PATH ?= /home/chinmay/ChinmayPersonalProjects/gopdfsuit
RUN_ARGS ?=
RUN_PROFILE ?= perf-run
# Optional: SKIP_BUILD=1 runs the selected profile binary with no cargo work.
# Example: make run SKIP_BUILD=1 RUN_ARGS="--export-context --export-chunks"
SKIP_BUILD ?= 0

RUN_BIN := ./target/$(RUN_PROFILE)/codehound

# Build the project
build:
	$(CARGO) build

# Run project tests
test:
	@RAYON_NUM_THREADS=4 $(CARGO) nextest run --test-threads 4 --no-fail-fast --status-level fail --final-status-level fail & nextest_pid=$$!; \
	$(CARGO) test --doc & doctest_pid=$$!; \
	wait $$nextest_pid; nextest_status=$$?; \
	wait $$doctest_pid; doctest_status=$$?; \
	test $$nextest_status -eq 0 -a $$doctest_status -eq 0

# Drop accumulated materialize roots from prior test/CLI runs.
# Safe while tests are not running; each run also prunes dead-PID roots.
clean-fixtures:
	rm -rf target/codehound-fixtures

# Check code for linting issues using clippy
lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings
	$(CARGO) fmt --check

# Public docs with warnings as errors (intra-doc links, missing docs on public API).
doc:
	RUSTDOCFLAGS='-D warnings' $(CARGO) doc --all-features --no-deps --locked

# Apply code formatting
fmt:
	$(CARGO) fmt

# Local full-catalog scan (summary only). CLI default pack is `recommended`;
# use RUN_ARGS='--profile recommended' for the CI pack. Override SCAN_PATH as needed.
#   make run RUN_ARGS="--export-context --export-chunks"
#   make run SKIP_BUILD=1   # no recompile; requires target/release/codehound already built
#
# Uses the optimized incremental `perf-run` profile by default. For publishable
# performance numbers, use `make run RUN_PROFILE=release`; dirty release LTO
# rebuilds can take minutes.
run:
	@if [ "$(SKIP_BUILD)" = "1" ]; then \
		test -x $(RUN_BIN) || { echo "missing $(RUN_BIN); run: make run  (or cargo build --profile $(RUN_PROFILE))"; exit 1; }; \
		echo ">>> SKIP_BUILD=1: running existing $(RUN_BIN)"; \
	else \
		echo ">>> ensuring $(RUN_PROFILE) binary is up to date (skips compile if nothing changed)..."; \
		$(CARGO) build --profile $(RUN_PROFILE); \
	fi
	@$(RUN_BIN) $(SCAN_PATH) --no-fail --no-terminal --profile all $(RUN_ARGS)

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
