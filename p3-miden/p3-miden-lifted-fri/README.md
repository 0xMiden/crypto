# p3-miden-lifted-fri

A polynomial commitment scheme (PCS) for *evaluation matrices* committed with
LMCS, using DEEP to batch evaluation claims and FRI to prove low degree.

This PCS is used by the lifted STARK prover/verifier crates in this workspace.

## Notation

- `log_lde_height`: log2 of the committed LDE domain size.
- `N`: number of evaluation points the verifier requests (generic const in APIs).
- `H`: trace subgroup (size depends on the outer protocol).
- `gK`: LDE evaluation coset (size `2^log_lde_height`).
- `tree index`: LMCS leaf index (bit-reversed position).

## What This Crate Does

- **Opens** one or more LMCS commitments at a fixed set of `N` evaluation points.
- **Batches** all opened columns into one DEEP quotient polynomial.
- **Proves/verifies** that the DEEP quotient is low degree via (batched) FRI.

The implementation is generic over `N`. The common STARK instantiation uses
`N = 2` (an out-of-domain point `z` and `z_next = z * omega_H`).

## Math Sketch

Given evaluation claims f_i(z_j), DEEP forms a quotient polynomial

```
Q(X) = ∑_i ∑_j α^i · β^j · (f_i(X) - f_i(z_j)) / (X - z_j)
```

so Q is low-degree iff all claims are consistent. Evaluations are stored in
bit-reversed order. **Lifting** treats shorter matrices as evaluations of
f_i(X^r) on the LDE domain (r = lde_height / height_i), achieved via
**upsampling** (row repetition in bit-reversed order). FRI then repeatedly
folds evaluations by the chosen arity to test low degree.

## Protocol Shape (Fiat-Shamir)

At a high level:

1. **Prover binds OOD evaluations** into the transcript (observed).
2. **DEEP PoW** then sample DEEP challenges `alpha` (column batching) and
   `beta` (point batching).
3. **FRI commit phase**: per-round commitment (observed), per-round PoW,
   sample folding challenge.
4. **Query PoW** then sample query indices.
5. **LMCS openings** for all queried indices (hints), verified against each
   commitment root.
6. **FRI query verification** and final polynomial checks.

Transcript ordering is security-critical; see the workspace `SECURITY.md`.

## Interface Contract (Caller Responsibility)

This crate is designed to be composed into a larger protocol (typically a
STARK). The caller is responsible for the following *normative* requirements:

- **Statement binding**: any per-statement data that is not already observed by
  this layer must be bound into the Fiat-Shamir challenger state by the
  application, identically on both prover and verifier. In particular:
  - commitment roots (LMCS roots for each commitment group),
  - widths / heights metadata,
  - `public_values` (if used by an outer STARK),
  - parameter choices (`PcsParams`, hash identifiers, domain separators).
- **Valid evaluation points**: each evaluation point must be outside the trace
  subgroup `H` and outside the LDE coset `gK`. If not, DEEP denominators can hit
  zero and verification must reject.
- **Commitment metadata**: commitment roots and matrix widths are statement data.
  For aligned trace commitments, widths must include alignment padding.

## Transcript Order (Observed vs Unobserved)

The transcript in this workspace distinguishes:

- **Observed** data: appended and absorbed into the challenger (`send_*`).
- **Unobserved** data: appended but *not* absorbed.
  - LMCS openings are written as **hints**.
  - PoW witnesses are stored as unobserved field elements (see `grind`).

Pseudocode for the PCS transcript shape:

```text
Observed:
  observe OOD evaluations (all commitments, all columns, all N points)
  grind(DEEP)
  sample alpha, beta

  for each FRI round:
    observe round commitment
    grind(FRI-round)
    sample beta_round

  observe final polynomial coefficients
  grind(query)
  sample query indices

Unobserved (hints):
  LMCS openings for input commitments (batch openings)
  LMCS openings for FRI round commitments (batch openings)
```

## Lifting / Uniform Height

This PCS assumes all committed matrices are presented at a *uniform* LDE height
`2^log_lde_height`. LMCS can represent mixed-height inputs via virtual
upsampling in bit-reversed order; to the PCS, those matrices simply look like
uniform-height commitments.

If you use lifting, the *outer protocol* (e.g. a STARK) must ensure the AIR and
statement are compatible with that lifted view (e.g. no reliance on wrap-around
rows unless explicitly constrained).

## Conventions & Preconditions

- **Bit-reversed rows**: LMCS stores evaluation rows in bit-reversed order.
- **Coset shift**: by convention the PCS uses `g = F::GENERATOR` for `gK`.
- **`log_lde_height`**: log2 of the committed LDE domain height.
- **Evaluation points**: the PCS expects each `z` to lie outside both the trace
  subgroup `H` and the LDE coset `gK` (otherwise DEEP denominators can hit zero).

## Alignment / Padding

For commitments built with `Lmcs::build_aligned_tree`, opened rows include
alignment padding (as recorded on the tree). Padding is a formatting convention
for transcript parsing; padded columns are treated as additional polynomials and
are only constrained to be low degree by this layer.

FRI round commitments commit a *single* matrix per round and therefore use
`Lmcs::build_tree` (unaligned) internally.

## Entry Points

| Path | Purpose |
|------|---------|
| `p3-miden-lifted-fri/src/prover.rs` | `open_with_channel` (prover) |
| `p3-miden-lifted-fri/src/verifier.rs` | `verify` / `verify_strict` / `verify_aligned` (verifier) |
| `p3-miden-lifted-fri/src/params.rs` | `PcsParams` |
| `p3-miden-lifted-fri/src/proof.rs` | `PcsTranscript` (export/debug view) |

## Code Map

| Module | Purpose |
|--------|---------|
| `p3-miden-lifted-fri/src/deep/` | DEEP quotient construction and verification |
| `p3-miden-lifted-fri/src/fri/` | FRI commit/query phases and folding |
| `p3-miden-lifted-fri/src/utils.rs` | Bit-reversal + Horner helpers |

## Transcript Types

`PcsTranscript`, `DeepTranscript`, `FriTranscript` are export/debug views
that reconstruct the full prover-verifier interaction (including challenges
and PoW witnesses) without re-running verification. They validate parsing
shape only — they do **not** guarantee proof validity. Production
verification uses the channel directly.

## Optimizations

- **Aligned openings**: rows are padded to a multiple of the sponge rate,
  ensuring a fixed number of permutations per leaf hash. Simplifies verifier
  parsing.
- **Uniform opening points**: all matrices (regardless of original height) are
  opened at the same domain points. DEEP batching uses a single set of
  z-values; no per-matrix domain reconstruction.
- **Recursive verifier benefits**: uniform height eliminates branching on
  matrix dimensions. The verifier logic is a single code path.

## Tests

- `p3-miden-lifted-fri/src/tests.rs`
- `p3-miden-lifted-fri/src/deep/tests.rs`
- `p3-miden-lifted-fri/src/fri/tests.rs`

## Security

Start with `SECURITY.md` at the workspace root (trust boundaries, transcript
ordering, DEEP/FRI invariants, and composition notes).

## License

Dual-licensed under MIT and Apache-2.0 at the workspace root.
