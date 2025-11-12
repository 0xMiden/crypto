.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables --------------------------------------------------------------------------------------

ALL_FEATURES_EXCEPT_ROCKSDB="concurrent executable hashmaps internal serde std"
DEBUG_OVERFLOW_INFO=RUSTFLAGS="-C debug-assertions -C overflow-checks -C debuginfo=2"
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

.PHONY: workspace-check
workspace-check: ## Runs a check that all packages have `lints.workspace = true`
	cargo workspace-lints

.PHONY: lint
lint: format fix clippy toml typos-check machete ## Run all linting tasks at once (Clippy, fixing, formatting, machete)

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generate and check documentation
	$(WARNINGS) cargo doc --all-features --keep-going --release

# --- testing -------------------------------------------------------------------------------------

.PHONY: test-default
test-default: ## Run tests with default features
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --profile default --release --features ${ALL_FEATURES_EXCEPT_ROCKSDB}

.PHONY: test-hashmaps
test-hashmaps: ## Run tests with `hashmaps` feature enabled
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --profile default --release --features hashmaps

.PHONY: test-no-std
test-no-std: ## Run tests with `no-default-features` (std)
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --profile default --release --no-default-features

.PHONY: test-smt-concurrent
test-smt-concurrent: ## Run only concurrent SMT tests
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --profile smt-concurrent --release

.PHONY: test-docs
test-docs:
	$(DEBUG_OVERFLOW_INFO) cargo test --doc --all-features

.PHONY: test-large-smt
test-large-smt: ## Run only large SMT tests
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --success-output immediate  --profile large-smt --release --features hashmaps,rocksdb

.PHONY: test
test: test-default test-hashmaps test-no-std test-docs test-large-smt ## Run all tests except concurrent SMT tests

# --- checking ------------------------------------------------------------------------------------

.PHONY: check
check: ## Check all targets and features for errors without code generation
	cargo check --all-targets --all-features

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Build with default features enabled
	cargo build --release

.PHONY: build-no-std
build-no-std: ## Build without the standard library
	cargo build --release --no-default-features --target wasm32-unknown-unknown

.PHONY: build-avx2
build-avx2: ## Build with avx2 support
	RUSTFLAGS="-C target-feature=+avx2" cargo build --release

.PHONY: build-avx512
build-avx512: ## Build with avx512 support
	RUSTFLAGS="-C target-feature=+avx512f,+avx512dq" cargo build --release

.PHONY: build-sve
build-sve: ## Build with sve support
	RUSTFLAGS="-C target-feature=+sve" cargo build --release

# --- benchmarking --------------------------------------------------------------------------------

.PHONY: bench
bench: ## Run crypto benchmarks
	cargo bench --features concurrent

.PHONY: bench-smt-concurrent
bench-smt-concurrent: ## Run SMT benchmarks with concurrent feature
	cargo run --release --features concurrent,executable -- --size 1000000

.PHONY: bench-large-smt-memory
bench-large-smt-memory: ## Run large SMT benchmarks with memory storage
	cargo run --release --features concurrent,hashmaps,executable -- --size 1000000

.PHONY: bench-large-smt-rocksdb
bench-large-smt-rocksdb: ## Run large SMT benchmarks with rocksdb storage
	cargo run --release --features concurrent,hashmaps,rocksdb,executable -- --storage rocksdb --size 1000000

.PHONY: bench-large-smt-rocksdb-open
bench-large-smt-rocksdb-open: ## Run large SMT benchmarks with rocksdb storage and open existing database
	cargo run --release --features concurrent,hashmaps,rocksdb,executable -- --storage rocksdb --open

.PHONY: bench-persisted-smt-forest
bench-persisted-smt-forest: ## Run large SMT benchmarks with rocksdb storage
	cargo run --release --features concurrent,hashmaps,rocksdb,executable -- --storage rocksdb --size 100000 --tree persisted-forest


# --- fuzzing --------------------------------------------------------------------------------

.PHONY: fuzz-smt
fuzz-smt: ## Run fuzzing for SMT
	cargo +nightly fuzz run smt --release --fuzz-dir miden-crypto-fuzz -- -max_len=10485760

# --- installing ----------------------------------------------------------------------------------

.PHONY: check-tools
check-tools: ## Checks if development tools are installed
	@echo "Checking development tools..."
	@command -v typos >/dev/null 2>&1 && echo "[OK] typos is installed" || echo "[MISSING] typos is not installed (run: make install-tools)"
	@command -v cargo nextest >/dev/null 2>&1 && echo "[OK] nextest is installed" || echo "[MISSING] nextest is not installed (run: make install-tools)"
	@command -v taplo >/dev/null 2>&1 && echo "[OK] taplo is installed" || echo "[MISSING] taplo is not installed (run: make install-tools)"
	@command -v cargo machete >/dev/null 2>&1 && echo "[OK] machete is installed" || echo "[MISSING] machete is not installed (run: make install-tools)"

.PHONY: install-tools
install-tools: ## Installs development tools required by the Makefile (typos, nextest, taplo, machete)
	@echo "Installing development tools..."
	cargo install typos-cli --locked
	cargo install cargo-nextest --locked
	cargo install taplo-cli --locked
	cargo install cargo-machete --locked
	@echo "Development tools installation complete!"
