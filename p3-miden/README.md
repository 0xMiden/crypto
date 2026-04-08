# Miden Plonky3

Miden-specific [Plonky3](https://github.com/Plonky3/Plonky3) crates.

The current focus of this workspace is a *lifted STARK* prover/verifier stack:
multi-trace proofs where traces of different heights are presented to the PCS
and verifier as a single uniform-height object via virtual lifting.

## Lifted STARK Stack

```text
miden-lifted-stark                (prover, verifier, shared types)
├── p3-miden-lifted-fri              (PCS: DEEP + FRI)
│   └── p3-miden-lmcs                (Merkle commitments with lifting)
├── miden-lifted-air              (AIR traits + symbolic analysis)
├── miden-stark-transcript              (Fiat-Shamir channels)
└── miden-stateful-hasher         (stateful hashers for LMCS)
```

## Workspace Crates

| Crate | Purpose |
|------|---------|
| `miden-lifted-stark` | Lifted STARK prover, verifier, and shared types (facade crate) |
| `miden-lifted-air` | Lifted AIR traits and symbolic constraint analysis |
| `p3-miden-lifted-fri` | PCS: DEEP quotient + FRI over LMCS commitments |
| `p3-miden-lmcs` | Lifted Matrix Commitment Scheme (uniform-height view) |
| `miden-stark-transcript` | Transcript channels (`ProverTranscript`, `VerifierTranscript`) |
| `miden-stateful-hasher` | Stateful hashers used by LMCS |
| `p3-miden-lifted-examples` | Example AIRs + benchmark binaries |

## Docs

- `docs/faq.md` (architecture Q&A)
- `docs/lifting.md` (math background for lifting)
- `SECURITY.md` (audit/review guide; transcript and composition notes)

## Where To Start (Code)

- Protocol flow: `miden-lifted-stark/src/prover/mod.rs` and `miden-lifted-stark/src/verifier/mod.rs`
- PCS layer: `p3-miden-lifted-fri/src/prover.rs` and `p3-miden-lifted-fri/src/verifier.rs`
- Commitment layer: `p3-miden-lmcs/src/lmcs.rs` and `p3-miden-lmcs/src/lifted_tree.rs`
- Math background: `docs/lifting.md`

## Build / Test

```bash
make check
make test
make test-parallel
make lint
make doc
```

## Run An Example

```bash
cargo run -p p3-miden-lifted-examples --release --bin lifted_keccak
```

## Security Disclaimer

This code is research/prototype quality and has not been independently audited.
Do not treat any default parameters as production-ready.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache-2.0](LICENSE-APACHE).
