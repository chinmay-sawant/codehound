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

# Run slopguard against a path. Override SCAN_PATH or RUN_ARGS as needed.
run:
	@$(CARGO) run --quiet -- $(SCAN_PATH) --no-fail --no-terminal $(RUN_ARGS)

# Run benchmarks. Set SAVE_BASELINE=1 to save a new baseline.
bench:
	$(CARGO) bench
bench-save:
	$(CARGO) bench -- --save-baseline main

# Generate a CHANGELOG entry stub.
changelog:
	@echo "## [unreleased] - $$(date +%Y-%m-%d)" && echo "" && echo "### Added" && echo "" && echo "### Changed" && echo "" && echo "### Fixed" && echo ""
