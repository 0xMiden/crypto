.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables --------------------------------------------------------------------------------------

WARNINGS=RUSTDOCFLAGS="-D warnings"

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Run Clippy with configs
	cargo clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: fix
fix: ## Run Fix with configs
	cargo +nightly fix --allow-staged --allow-dirty --all-targets --all-features

.PHONY: format
format: ## Run Format using nightly toolchain
	cargo +nightly fmt --all

.PHONY: format-check
format-check: ## Run Format using nightly toolchain but only in check mode
	cargo +nightly fmt --all --check

.PHONY: machete
machete: ## Runs machete to find unused dependencies
	cargo machete

.PHONY: toml
toml: ## Runs Format for all TOML files
	taplo fmt

.PHONY: toml-check
toml-check: ## Runs Format for all TOML files but only in check mode
	taplo fmt --check --verbose

.PHONY: typos-check
typos-check: ## Runs spellchecker
	typos

.PHONY: lint
lint: format fix clippy toml typos-check ## Run all linting tasks at once

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generate and check documentation
	$(WARNINGS) cargo doc --all-features --keep-going --release

# --- testing -------------------------------------------------------------------------------------

.PHONY: test
test: ## Run tests with default features
	cargo test --workspace

.PHONY: test-parallel
test-parallel: ## Run tests with parallel feature
	cargo test --workspace --features parallel

.PHONY: test-release
test-release: ## Run tests in release mode
	cargo test --workspace --profile test-release

.PHONY: test-all
test-all: test test-parallel ## Run all test variants

# --- checking ------------------------------------------------------------------------------------

.PHONY: check
check: ## Check all targets and features for errors without code generation
	cargo check --all-targets --all-features

.PHONY: check-features
check-features: ## Check the supported non-default feature combinations
	cargo check --workspace --all-targets --no-default-features
	cargo check --workspace --all-targets --features parallel
	cargo check -p p3-miden-lmcs --all-targets --features testing
	cargo check -p p3-miden-lifted-fri --all-targets --features testing

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Build with release profile
	cargo build --release

.PHONY: build-no-std
build-no-std: ## Build without the standard library (for embedded targets)
	cargo build --release --no-default-features --target wasm32-unknown-unknown

.PHONY: build-avx2
build-avx2: ## Build with avx2 support
	RUSTFLAGS="-C target-feature=+avx2" cargo build --release

.PHONY: build-avx512
build-avx512: ## Build with avx512 support
	RUSTFLAGS="-C target-feature=+avx512f,+avx512dq" cargo build --release

# --- benchmarking --------------------------------------------------------------------------------

.PHONY: bench
bench: ## Run benchmarks
	cargo bench --workspace --features testing

# --- installing ----------------------------------------------------------------------------------

.PHONY: check-tools
check-tools: ## Checks if development tools are installed
	@echo "Checking development tools..."
	@command -v typos >/dev/null 2>&1 && echo "[OK] typos is installed" || echo "[MISSING] typos is not installed (run: make install-tools)"
	@command -v cargo nextest >/dev/null 2>&1 && echo "[OK] nextest is installed" || echo "[MISSING] nextest is not installed (run: make install-tools)"
	@command -v taplo >/dev/null 2>&1 && echo "[OK] taplo is installed" || echo "[MISSING] taplo is not installed (run: make install-tools)"
	@command -v cargo machete >/dev/null 2>&1 && echo "[OK] machete is installed" || echo "[MISSING] machete is not installed (run: make install-tools)"

.PHONY: install-tools
install-tools: ## Installs development tools required by the Makefile
	@echo "Installing development tools..."
	cargo install typos-cli --locked
	cargo install cargo-nextest --locked
	cargo install taplo-cli --locked
	cargo install cargo-machete --locked
	@echo "Development tools installation complete!"
