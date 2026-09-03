.DEFAULT_GOAL := build

CARGO ?= cargo
PYTHON ?= python3
WASM_BINDGEN_VERSION := 0.2.127
ifeq ($(OS),Windows_NT)
EXEEXT := .exe
endif
RUST_BIN := $(CURDIR)/target/debug/tailcat$(EXEEXT)

.PHONY: build release test check interop interop-full interop-web web web-dist web-tools tidy

build: ## Build the native Rust CLI and web tools
	$(CARGO) build --locked --bins

release: ## Build optimized native Rust binaries
	$(CARGO) build --locked --release --bins

test: ## Run Rust unit and integration tests
	$(CARGO) test --locked --all-targets

check: ## Check formatting, compiler warnings, and lints
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --locked --all-targets -- -D warnings

interop: build ## Compare Rust with a pinned, externally fetched Go implementation
	$(PYTHON) scripts/check-interop.py --binary "$(RUST_BIN)"

interop-full: build ## Run the external implementation's complete CLI compatibility suite
	$(PYTHON) scripts/check-interop.py --binary "$(RUST_BIN)" --full-cli

interop-web: build web-dist ## Also verify the Rust browser against the external implementation
	$(PYTHON) scripts/check-interop.py --binary "$(RUST_BIN)" --web-dist "$(CURDIR)/dist"

web-tools: ## Install the Rust browser build prerequisites
	rustup target add wasm32-unknown-unknown
	$(CARGO) install wasm-bindgen-cli --version $(WASM_BINDGEN_VERSION) --locked

web: ## Build and run the native Rust web demo server
	$(CARGO) run --locked --bin tailcat-web

web-dist: ## Build the Rust/Wasm browser demo into dist/
	$(CARGO) run --locked --bin tailcat-webdist -- -o dist

tidy: ## Resolve native Rust dependency lockfiles
	$(CARGO) generate-lockfile
	$(CARGO) generate-lockfile --manifest-path wasm/Cargo.toml
