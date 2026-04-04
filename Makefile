.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# -- variables --------------------------------------------------------------------------------------

MIDDEN_CRYPTO_ALL_FEATURES_EXCEPT_ROCKSDB="miden-crypto/concurrent miden-crypto/executable miden-crypto/internal miden-crypto/serde miden-crypto/std"
P3_PACKAGES=-p p3-miden-dev-utils -p p3-miden-lifted-air -p p3-miden-lifted-examples -p p3-miden-lifted-fri -p p3-miden-lifted-stark -p p3-miden-lmcs -p p3-miden-stateful-hasher -p p3-miden-transcript
P3_PARALLEL_FEATURES="p3-miden-lifted-examples/parallel p3-miden-lifted-fri/parallel p3-miden-lifted-stark/parallel p3-miden-lmcs/parallel"
P3_TESTING_FEATURES="p3-miden-lifted-fri/testing p3-miden-lmcs/testing"
WARNINGS=RUSTDOCFLAGS="-D warnings"

# -- linting --------------------------------------------------------------------------------------

.PHONY: clippy
clippy: ## Run Clippy with configs (alias for xclippy)
	cargo xclippy
	cargo clippy $(P3_PACKAGES) --all-targets --all-features -- -D warnings

.PHONY: xclippy
xclippy: ## Run Clippy with the curated workspace lint set
	cargo xclippy

.PHONY: fix
fix: ## Run Fix with configs (alias for xclippy-fix)
	cargo xclippy-fix

.PHONY: xclippy-fix
xclippy-fix: ## Run Clippy with --fix using the same lint set as xclippy
	cargo xclippy-fix


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

.PHONY: cargo-deny
cargo-deny: ## Run cargo-deny to check dependencies for security vulnerabilities and license compliance
	cargo deny check

.PHONY: zeroize-audit
zeroize-audit: ## Run Zeroize audit using rustdoc JSON
	cargo +nightly rustdoc -p miden-crypto --all-features -- -Zunstable-options --output-format json --document-private-items
	@target_dir="$${CARGO_TARGET_DIR:-target}"; \
	if [ "$$target_dir" = "/" ]; then target_dir=target; fi; \
	cargo run --quiet --manifest-path tools/zeroize-audit/Cargo.toml -- "$$target_dir/doc/miden_crypto.json"

.PHONY: lint
lint: clippy fix format toml typos-check machete cargo-deny ## Run all linting tasks at once (Clippy, fixing, formatting, machete, cargo-deny)

# --- docs ----------------------------------------------------------------------------------------

.PHONY: doc
doc: ## Generate and check documentation for workspace crates only
	rm -rf "${CARGO_TARGET_DIR:-target}/doc"
	RUSTDOCFLAGS="--enable-index-page -Zunstable-options -D warnings" cargo +nightly doc --all-features --keep-going --release --no-deps

# --- testing -------------------------------------------------------------------------------------

.PHONY: test-default
test-default: ## Run tests with default features
	cargo nextest run --workspace --profile default --cargo-profile test-release --features ${MIDDEN_CRYPTO_ALL_FEATURES_EXCEPT_ROCKSDB}

.PHONY: test-no-std
test-no-std: ## Run tests with `no-default-features` (std)
	cargo nextest run --workspace --profile default --cargo-profile test-release --no-default-features

.PHONY: test-p3-parallel
test-p3-parallel: ## Run workspace tests with p3 parallel support enabled
	cargo nextest run --workspace --profile default --cargo-profile test-release --features ${P3_PARALLEL_FEATURES}

.PHONY: test-p3-testing
test-p3-testing: ## Run p3 crates that require their `testing` feature
	cargo nextest run --workspace --profile default --cargo-profile test-release --features ${P3_TESTING_FEATURES}

.PHONY: test-smt-concurrent
test-smt-concurrent: ## Run only concurrent SMT tests
	cargo nextest run --workspace --profile smt-concurrent --cargo-profile test-release

.PHONY: test-docs
test-docs:
	cargo test --workspace --doc --all-features --profile test-release

.PHONY: test-large-smt
test-large-smt: ## Run only large SMT tests
	cargo nextest run --workspace --success-output immediate --profile large-smt --cargo-profile test-release --features miden-crypto/rocksdb

.PHONY: test
test: test-default test-no-std test-p3-parallel test-p3-testing test-docs test-large-smt ## Run all tests except concurrent SMT tests

# --- checking ------------------------------------------------------------------------------------

.PHONY: check
check: ## Check all targets and features for errors without code generation
	cargo check --workspace --all-targets --all-features

.PHONY: check-features
check-features: ## Check workspace feature combinations
	cargo check --workspace --all-targets --no-default-features
	cargo check --workspace --all-targets --features ${MIDDEN_CRYPTO_ALL_FEATURES_EXCEPT_ROCKSDB}
	cargo check --workspace --all-targets --features ${P3_PARALLEL_FEATURES}
	cargo check -p p3-miden-lmcs --all-targets --features testing
	cargo check -p p3-miden-lifted-fri --all-targets --features testing

.PHONY: check-fuzz
check-fuzz: ## Check miden-crypto-fuzz compilation
	cd miden-crypto-fuzz && cargo check

# --- building ------------------------------------------------------------------------------------

.PHONY: build
build: ## Build with default features enabled
	cargo build --workspace --release

.PHONY: build-no-std
build-no-std: ## Build without the standard library
	cargo build --workspace --release --no-default-features --target wasm32-unknown-unknown

.PHONY: build-target-miden
build-target-miden: ## Build `miden-field` for wasm32-wasip2 with `--cfg miden`
	RUSTFLAGS="$${RUSTFLAGS:+$$RUSTFLAGS }--cfg miden" cargo build --release -p miden-field --target wasm32-wasip2

.PHONY: build-avx2
build-avx2: ## Build with avx2 support
	RUSTFLAGS="-C target-feature=+avx2" cargo build --workspace --release

.PHONY: build-avx512
build-avx512: ## Build with avx512 support
	RUSTFLAGS="-C target-feature=+avx512f,+avx512dq" cargo build --workspace --release

.PHONY: build-sve
build-sve: ## Build with sve support
	RUSTFLAGS="-C target-feature=+sve" cargo build --workspace --release

# --- benchmarking --------------------------------------------------------------------------------

.PHONY: bench
bench: ## Run crypto benchmarks
	cargo bench --features concurrent

.PHONY: bench-smt-concurrent
bench-smt-concurrent: ## Run SMT benchmarks with concurrent feature
	cargo run --release --features concurrent,executable -- --size 1000000

.PHONY: bench-large-smt-memory
bench-large-smt-memory: ## Run large SMT benchmarks with memory storage
	cargo run --release --features concurrent,executable -- --size 1000000

.PHONY: bench-large-smt-rocksdb
bench-large-smt-rocksdb: ## Run large SMT benchmarks with rocksdb storage
	cargo run --release --features concurrent,rocksdb,executable -- --storage rocksdb --size 1000000

.PHONY: bench-large-smt-rocksdb-open
bench-large-smt-rocksdb-open: ## Run large SMT benchmarks with rocksdb storage and open existing database
	cargo run --release --features concurrent,rocksdb,executable -- --storage rocksdb --open

# --- fuzzing --------------------------------------------------------------------------------

.PHONY: fuzz-smt
fuzz-smt: ## Run fuzzing for SMT (sequential vs parallel consistency)
	cargo +nightly fuzz run smt --release --fuzz-dir miden-crypto-fuzz -- -max_len=10485760

.PHONY: fuzz-word
fuzz-word: ## Run fuzzing for Word serialization
	cargo +nightly fuzz run word --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-merkle
fuzz-merkle: ## Run fuzzing for Merkle tree serialization
	cargo +nightly fuzz run merkle --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-merkle-store
fuzz-merkle-store: ## Run fuzzing for MerkleStore deserialization
	cargo +nightly fuzz run merkle_store --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-smt-serde
fuzz-smt-serde: ## Run fuzzing for SMT serialization
	cargo +nightly fuzz run smt_serde --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-mmr
fuzz-mmr: ## Run fuzzing for MMR structures serialization
	cargo +nightly fuzz run mmr --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-crypto
fuzz-crypto: ## Run fuzzing for cryptographic types serialization
	cargo +nightly fuzz run crypto --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-aead
fuzz-aead: ## Run fuzzing for AEAD decryption paths
	cargo +nightly fuzz run aead --release --fuzz-dir miden-crypto-fuzz

.PHONY: fuzz-signatures
fuzz-signatures: ## Run fuzzing for DSA signature deserialization
	cargo +nightly fuzz run signatures --release --fuzz-dir miden-crypto-fuzz

# --- installing ----------------------------------------------------------------------------------

.PHONY: check-tools
check-tools: ## Checks if development tools are installed
	@echo "Checking development tools..."
	@command -v typos >/dev/null 2>&1 && echo "[OK] typos is installed" || echo "[MISSING] typos is not installed (run: make install-tools)"
	@command -v cargo nextest >/dev/null 2>&1 && echo "[OK] nextest is installed" || echo "[MISSING] nextest is not installed (run: make install-tools)"
	@command -v taplo >/dev/null 2>&1 && echo "[OK] taplo is installed" || echo "[MISSING] taplo is not installed (run: make install-tools)"
	@command -v cargo machete >/dev/null 2>&1 && echo "[OK] machete is installed" || echo "[MISSING] machete is not installed (run: make install-tools)"
	@command -v cargo deny >/dev/null 2>&1 && echo "[OK] cargo-deny is installed" || echo "[MISSING] cargo-deny is not installed (run: make install-tools)"

.PHONY: install-tools
install-tools: ## Installs development tools required by the Makefile (typos, nextest, taplo, machete, cargo-deny)
	@echo "Installing development tools..."
	cargo install typos-cli --locked
	cargo install cargo-nextest --locked
	cargo install taplo-cli --locked
	cargo install cargo-machete --locked
	cargo install cargo-deny --locked
	@echo "Development tools installation complete!"
