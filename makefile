CARGO ?= cargo

ifeq ($(OS),Windows_NT)
ifeq ($(shell where cargo 2>NUL),)
CARGO := C:\\Windows\\Sysnative\\wsl.exe --cd $(WSL_REPO_ROOT) cargo
endif
endif

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

run:
	$(CARGO) run -- /home/chinmay/ChinmayPersonalProjects/gopdfsuit