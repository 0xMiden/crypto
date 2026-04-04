# p3-miden-lmcs

Lifted Matrix Commitment Scheme (LMCS): a Merkle commitment scheme for *multiple
evaluation matrices* of different (power-of-two) heights, presented to the
verifier as a single uniform-height object.

LMCS is the commitment layer used by `p3-miden-lifted-fri` and the lifted STARK
prover/verifier crates in this workspace.

## Motivation

In multi-AIR designs, traces have different heights. Without lifting, the PCS
must track per-matrix heights, DEEP batching needs per-matrix domain logic, and
recursive verifiers require height-dependent branching. LMCS provides a
uniform-height view that eliminates all of this, and makes it easier to swap in
alternative polynomial commitment schemes (e.g. STIR or WHIR) downstream.

## Notation

- `N`: maximum (lifted) height among all matrices committed together.
- `n`: height of a particular matrix.
- `r = N / n`: lift ratio (a power of two).
- `i`: a *tree index* in `0..N` (LMCS leaf index).
- **Bit-reversed order**: row `i` corresponds to the coset point `g * omega^{bitrev(i)}`.

## What LMCS Gives You

- Commit to several matrices at once, even when their heights differ.
- Open many leaf indices in one batch.
- A uniform-height view: shorter matrices are virtually upsampled (row
  repetition) so downstream code can avoid height-dependent branching.

## Model: Bit-Reversed Rows + Virtual Upsampling

LMCS is designed for matrices that store evaluations in **bit-reversed order**
over a two-adic coset.

If a matrix has height `n` and the maximum height in the group is `N = r * n`
(with `r` a power of two), LMCS conceptually commits to the *lifted* matrix of
height `N` obtained by repeating each row `r` times in bit-reversed layout.

For evaluation vectors, this corresponds to committing to the lifted polynomial
`f'(X) = f(X^r)` over the larger domain.

## Worked Example (Two Heights)

Suppose you commit to two matrices `A` and `B`:

- `A` has height `n = 4`.
- `B` has height `N = 8` (so `B` is already max height).

Then `r = N / n = 2`, and LMCS conceptually lifts `A` to height 8 by repeating
each row twice in *tree index order*:

```text
i:      0  1  2  3  4  5  6  7
A row:  0  0  1  1  2  2  3  3        (row_A(i) = A[i >> 1])
B row:  0  1  2  3  4  5  6  7
```

All hashing and openings are defined on this uniform-height view.

## Leaf Hashing (Commitment Preimage)

For each leaf index `i` (in the lifted, max-height tree), LMCS hashes the
concatenation of all lifted rows at that index, in **matrix order**:

```text
leaf(i) = squeeze( absorb( row_0(i) || row_1(i) || ... || row_{t-1}(i) || salt? ) )
```

- Rows are absorbed left-to-right.
- Matrices must be supplied **sorted by height** (shortest to tallest).
- Optional salt (hiding LMCS) is absorbed after all matrix rows.

Reordering matrices or columns changes the commitment.

## Alignment (Transcript Formatting)

For sponge-style hashers, absorbing a row may implicitly pad with zeros up to the
sponge rate. LMCS exposes this as an *alignment* parameter.

- `build_tree`: no padding in transcript hints (alignment = 1).
- `build_aligned_tree`: transcript hints pad each opened row to the hasher
  alignment; the aligned widths are recorded on the tree.

Important: LMCS does **not** enforce that padded values are zero; padding is a
formatting convention. If your protocol needs "padding must be zero", it must
constrain that elsewhere.

Alignment has two distinct roles:

- **Hash semantics**: sponge-style hashers may *implicitly* pad absorbed inputs.
- **Hint formatting**: `build_aligned_tree` pads *opened rows* in transcript hints
  so verifiers can parse fixed-size chunks.

## What LMCS Proves (And Doesn't)

LMCS proves:

- Opened rows are consistent with the committed Merkle root under the configured
  hash/compression functions.

LMCS does not prove:

- Any semantic statement about the *original* heights beyond the statement data
  the caller supplies (lifting is indistinguishable from explicit repetition).
- Periodicity or any AIR-specific structure.

## API Entry Points

| Item | Purpose |
|------|---------|
| `LmcsConfig` / `HidingLmcsConfig` | Configure primitives and build trees |
| `Lmcs::build_tree` | Build a tree (no transcript padding) |
| `Lmcs::build_aligned_tree` | Build a tree (alignment-aware hint padding) |
| `LmcsTree::prove_batch` | Write a batch opening (hints) |
| `Lmcs::open_batch` | Verify a batch opening (reads hints) |
| `BatchProof` / `Proof` | Parse/export helpers (not production verification) |

## Invariants (Caller Responsibility)

- Matrix heights are powers of two.
- Matrices are supplied in ascending height order.
- `widths` / `log_max_height` provided to verification match the committed tree.
- Query indices are in `0..2^log_max_height`.

If these invariants do not hold, verification should fail via parse error,
`InvalidProof`, or root mismatch; it must not silently accept.

## Code Map

| Path | Purpose |
|------|---------|
| `p3-miden-lmcs/src/lmcs.rs` | `LmcsConfig` implementation; `open_batch` |
| `p3-miden-lmcs/src/lifted_tree.rs` | Tree construction + proving |
| `p3-miden-lmcs/src/proof.rs` | `BatchProof` / `Proof` types |
| `p3-miden-lmcs/src/utils.rs` | Row hashing + width/alignment helpers |

## Security

Start with `SECURITY.md` at the workspace root for trust boundaries, canonical
hint parsing, and composition notes.

## License

Dual-licensed under MIT and Apache-2.0 at the workspace root.
