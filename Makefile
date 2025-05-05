.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables --------------------------------------------------------------------------------------

WARNINGS=RUSTDOCFLAGS="-D warnings"
DEBUG_OVERFLOW_INFO=RUSTFLAGS="-C debug-assertions -C overflow-checks -C debuginfo=2"

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Run Clippy with configs
	$(WARNINGS) cargo +nightly clippy --workspace --all-targets --all-features


.PHONY: fix
fix: ## Run Fix with configs
	cargo +nightly fix --allow-staged --allow-dirty --all-targets --all-features


.PHONY: format
format: ## Run Format using nightly toolchain
	cargo +nightly fmt --all


.PHONY: format-check
format-check: ## Run Format using nightly toolchain but only in check mode
	cargo +nightly fmt --all --check


.PHONY: lint
lint: format fix clippy ## Run all linting tasks at once (Clippy, fixing, formatting)

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generate and check documentation
	$(WARNINGS) cargo doc --all-features --keep-going --release

# --- testing -------------------------------------------------------------------------------------

.PHONY: test-default
test-default: ## Run tests with default features
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --profile default --release --all-features

.PHONY: test-smt-hashmaps
test-smt-hashmaps: ## Run tests with `smt_hashmaps` feature enabled
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --profile default --release --features smt_hashmaps

.PHONY: test-no-std
test-no-std: ## Run tests with `no-default-features` (std)
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --profile default --release --no-default-features

.PHONY: test-smt-concurrent
test-smt-concurrent: ## Run only concurrent SMT tests
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --profile smt-concurrent --release --all-features

.PHONY: test-large-smt
test-large-smt: ## Run only concurrent SMT tests
	$(DEBUG_OVERFLOW_INFO) cargo nextest run --success-output immediate  --profile large-smt --release --all-features --test-threads=1

.PHONY: test
test: test-default test-smt-hashmaps test-no-std ## Run all tests except concurrent SMT tests

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

# --- fuzzing --------------------------------------------------------------------------------

.PHONY: fuzz-smt
fuzz-smt: ## Run fuzzing for SMT
	cargo +nightly fuzz run smt --release --fuzz-dir miden-crypto-fuzz -- -max_len=10485760
