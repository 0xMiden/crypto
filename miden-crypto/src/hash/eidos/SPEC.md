# Eidos - Design and Specification

## Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture) - layering rationale, design constraints, module layout, type surface
3. [Shared BLAKE3 compression core](#3-shared-blake3-compression-core) - `p`-parameterised core, IV, G, message schedule, output equations
4. [BlakeG mode](#4-blakeg-mode) - Goldilocks specialization: packing, signature, init, padding, wide output
5. [Security claims](#5-security-claims) - bounds, indifferentiability, output finalizer
6. [Design rationale](#6-design-rationale) - why this set of choices
7. [AEAD](#7-aead) - Encrypt-then-MAC: CTR keystream + Wegman-Carter-Shoup tag
8. [Forward compatibility with standard BLAKE3 compression](#8-forward-compatibility-with-standard-blake3-compression)
9. [References](#9-references)
10. [Appendix A - Notation glossary](#appendix-a---notation-glossary)

---

## 1. Overview

Eidos is a cryptographic hash function with three conceptual layers:

- **BLAKE3 core** - the shared 7-round BLAKE3 compression core over `u32` words. This layer is mode-agnostic and is deliberately specified so that a future standard-BLAKE3-compression VM operation can reuse it.
- **BlakeG mode** - a Goldilocks-tailored specialization of that core. BlakeG owns the field packing, the 252-bit subspace mask, and the init-time binding of Eidos length/domain information.
- **Eidos** - the public hash API built on BlakeG mode. Eidos owns padding, domain assignment, length binding, and the Miden-facing API surface.

Goldilocks is the prime field `F_M` with modulus:

```text
M = 2^64 - 2^32 + 1
```

A `Felt` is one canonical element of this field, represented by an integer in `[0, M)`. A `Word = [Felt; 4]` is Eidos's 4-Felt digest type.

Security target:

- **Collision resistance: 126 bits** (birthday bound)
- **Preimage resistance: 252 bits**

The 2-bit gap below BLAKE3's standard 128-bit collision target comes from the Goldilocks felt-packing convention, not from the BLAKE3 core. See Section 5.

This document specifies BlakeG as a BLAKE3 mode. In particular, BlakeG uses BLAKE3's 7-round message schedule and BLAKE3's truncated compression output `v_low ^ v_high`.

---

## 2. Architecture

### 2.1 Layering rationale

The work splits cleanly along the field/VM boundary:

| | Shared core | BlakeG mode | Eidos |
|---|---|---|---|
| Concern | BLAKE3 7-round ARX compression core | Goldilocks packing and field-safe output | Padding, framing, domain separation, public API |
| Data type | `u32` lanes | packed `Felt` words at boundaries | `Word` / `Felt` / bytes |
| Reusability | Future BlakeG and standard-BLAKE3-compression operations | Goldilocks projects | Miden framing choices |
| Audit surface | BLAKE3 compression-function cryptanalysis | packing, masking, init binding | padding/domain/length correctness |

The important forward-compatibility rule is: statements about field packing, masking, and init-time injection are BlakeG-mode statements, not properties of the shared BLAKE3 core. A future VM operation for standard BLAKE3 compression should be able to select the same core and different mode wiring.

### 2.2 Design constraints

The spec is constrained by four engineering goals:

- **MASM-friendly steady state.** The current Miden VM pattern is `adv_pipe; hperm` per block after a small init prologue. For BlakeG naming, the equivalent target pattern is `adv_pipe; bcompress`. No per-block counter, flag, domain, or length values should be pushed in BlakeG mode.
- **AEAD support.** The compression interface exposes the full 16-`u32` output, which the AEAD (Section 7) uses as keystream; the pseudorandomness of that output is an explicit AEAD assumption (Section 7).
- **Modularity.** BLAKE3 core logic, BlakeG field packing, and Eidos framing should stay separable. Padding, domain assignment, and length binding belong to Eidos, while packing and masking belong to BlakeG mode.
- **Future standard-BLAKE3 compression support.** BlakeG-specific choices stay scoped to BlakeG mode, so a future sibling operation can reuse the shared core for standard BLAKE3 compression (Section 8).

### 2.3 Module layout

```text
miden-crypto/src/hash/eidos/
  mod.rs           public re-exports: BlakeG, Eidos
  primitive.rs     BlakeG: BLAKE3 compression over Goldilocks
  framing.rs       Eidos: public API + framing constants
  SPEC.md          this document
  tests.rs         tests for both layers
```

### 2.4 Type surface

```rust
// Field layer
pub struct BlakeG;
impl BlakeG {
    pub const ROUNDS: usize = 7;
    pub const STATE_WORDS: usize = 8;        // u32 lanes
    pub const BLOCK_WORDS: usize = 16;       // u32 lanes per block
    pub fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8];
}

// VM layer
pub struct Eidos;
impl Eidos {
    pub fn hash(bytes: &[u8]) -> Word;
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Word;
    pub fn hash_elements_in_domain<E: BasedVectorSpace<Felt>>(elements: &[E], domain: Felt) -> Word;
    pub fn merge(values: &[Word; 2]) -> Word;
    pub fn merge_many(values: &[Word]) -> Word;
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word;
}
```

The hash `compress` exposes only the digest half. The AEAD (Section 7) uses the full 16-`u32` output as keystream; Section 4.7 specifies that wide output.

---

## 3. Shared BLAKE3 compression core

### 3.1 Core inputs

The shared core is a BLAKE3 compression-core function over 32-bit words:

```text
core(h: [u32; 8], m: [u32; 16], p: [u32; 4]) -> ([u32; 8], [u32; 8])
```

where:

- `h[0..8)` is the input chaining value.
- `m[0..16)` is the 512-bit block.
- `p[0..4)` supplies the final four initialization words of the BLAKE3 state.

Throughout this spec, `p` denotes this BLAKE3 parameter-tail input.

The core initializes the 16-word working state as:

```text
v[0..8)   = h[0..8)
v[8..12)  = IV[0..4)
v[12..16) = p[0..4)
```

Standard BLAKE3 compression chooses:

```text
p = [counter_lo, counter_hi, block_len, flags]
```

BlakeG mode chooses:

```text
p = [IV[4], IV[5], IV[6], IV[7]]
```

This separation is intentional. The shared core takes `p` as an argument rather than hardcoding BlakeG's `IV[4..8)` choice, and BlakeG fills `v[12..16)` with fixed IV constants rather than its own data, so a future standard-BLAKE3 operation can reuse the same core and route real `(counter, block_len, flags)` into those slots.

### 3.2 IV constants

BLAKE3 uses the following IV constants:

```text
IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]
```

These constants are shared by BlakeG and any future standard-BLAKE3-compression operation.

### 3.3 Round function

The round function is BLAKE3's 7-round ARX permutation core. BlakeG inherits this `G` function and column/diagonal layout unchanged.

For each round, the eight `G` calls are:

```text
G(v[0], v[4], v[8],  v[12], m[s[0]],  m[s[1]])
G(v[1], v[5], v[9],  v[13], m[s[2]],  m[s[3]])
G(v[2], v[6], v[10], v[14], m[s[4]],  m[s[5]])
G(v[3], v[7], v[11], v[15], m[s[6]],  m[s[7]])

G(v[0], v[5], v[10], v[15], m[s[8]],  m[s[9]])
G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]])
G(v[2], v[7], v[8],  v[13], m[s[12]], m[s[13]])
G(v[3], v[4], v[9],  v[14], m[s[14]], m[s[15]])
```

`G(a, b, c, d, x, y)` is:

```text
a = a + b + x        mod 2^32
d = (d ^ a) >>> 16
c = c + d            mod 2^32
b = (b ^ c) >>> 12
a = a + b + y        mod 2^32
d = (d ^ a) >>> 8
c = c + d            mod 2^32
b = (b ^ c) >>> 7
```

### 3.4 Message schedule

BLAKE3 uses a single message permutation repeatedly. Let:

```text
MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
```

The 7 round schedules are the identity followed by repeated applications of this permutation:

```text
MSG_SCHEDULE = [
    [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15],
    [ 2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8],
    [ 3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1],
    [10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6],
    [12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4],
    [ 9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7],
    [11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13],
]
```

This BLAKE3 schedule is normative for BlakeG.

### 3.5 Core output

After 7 rounds, let `v'` be the permuted 16-word working state. BLAKE3 derives its compression output by XOR-folding words from this state:

```text
low[i]  = v'[i]     ^ v'[i + 8]    for i in 0..8
high[i] = v'[i + 8] ^ h[i]         for i in 0..8
```

When BLAKE3 compression is used to produce a chaining value, it uses `low`, the folded 8-word value, as the next 256-bit chaining value. The `high` half carries BLAKE3's extended output; BlakeG exposes it as the wide output of Section 4.7, which the AEAD uses as keystream (Section 7).

BlakeG mode follows the same folding rule for the next chaining value. It then applies BlakeG's field mask to odd words of that folded 8-word value before packing into Felts.

---

## 4. BlakeG mode

### 4.1 Mode specialization

BlakeG is the Goldilocks-field mode of the shared BLAKE3 core:

```text
blakeg_core(h, m):
    (low, high) = core(h, m, [IV[4], IV[5], IV[6], IV[7]])
    return mask_odd_lanes(low)
```

BlakeG intentionally drops standard BLAKE3's per-call `(counter_lo, counter_hi, block_len, flags)` inputs. Eidos binds the stream-wide information that it needs (its domain tag and length) once into the initial chaining value instead. This keeps the steady-state VM loop to one block load and one compression call:

```text
adv_pipe        # see Appendix A: supplies exactly one 8-Felt compression block
bcompress       # the BlakeG-mode compression; current implementations may still
                # spell this `hperm` while the chiplet is being reused
```

The important property is the cost shape: no per-block stack traffic except loading the next block and invoking the BlakeG compression. The full init prologue and steady-state loop are spelled out in Section 6.1.

The fixed BLAKE3-tail `p` value and the Eidos initialization play different roles. The value `p = [IV[4], IV[5], IV[6], IV[7]]` is used on every BlakeG compression call only to fill the BLAKE3 working-state tail `v[12..16)`. Eidos domain separation and length binding live in the chaining-value input `h = cv`. Section 4.4 defines `cv_0` from the domain tag, and each masked folded output becomes the next `cv`, so the tag is injected once at initialization and then propagates through the compression chain.

### 4.2 Goldilocks packing convention

At the Miden stack boundary, BlakeG represents the chaining value and digest as a `Word = [Felt; 4]`. Internally, the BLAKE3 core represents the same chaining value as eight `u32` lanes. At the input boundary, every canonical Goldilocks Felt is decomposed into two `u32` lanes:

```text
unpack(felt) -> (lo, hi)
    lo = felt mod 2^32
    hi = floor(felt / 2^32)
```

The even-indexed `u32` lane is the low half of the Felt. The odd-indexed `u32` lane is the high half. Since every Felt is in `[0, M)`, both halves are canonical `u32` values. Thus BlakeG can accept arbitrary canonical Felts as inputs and recover their canonical limb decomposition.

At the output boundary, BlakeG applies its current mask-and-pack finalizer:

```text
pack_masked(lo: u32, hi: u32) -> Felt
    = Felt::from_u64(((hi & 0x7fff_ffff) as u64) << 32 | lo as u64)
```

Why mask the top bit on output: a fully utilized 64-bit word can exceed the Goldilocks modulus `M = 2^64 - 2^32 + 1`. Masking the top bit forces every output Felt into `[0, 2^63)`, which is strictly below `M` and therefore canonical in Goldilocks. This is an output-finalization rule, not an input restriction.

This mask is **not** a property of the shared BLAKE3 core. A future standard-BLAKE3-compression operation should expose raw `u32` lanes, for example one `u32` per Felt, without this two-lane packed mask.

### 4.3 Compression signature

The BlakeG-mode compression operation is:

```rust
pub fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8]
```

Equivalently at the Miden stack boundary:

```text
bcompress(cv: Felt^4, block: Felt^8) -> Felt^4
```

BlakeG-mode `bcompress` accepts canonical Goldilocks Felts as inputs. The chaining value and block Felts are decoded into `u32` lanes using the decomposition in Section 4.2. The returned chaining value is then masked and packed, so BlakeG outputs live in `[0, 2^63)^4` even though inputs need not.

Implementation:

```text
1. Decode `cv` and `block` using the canonical Felt decomposition from Section
   4.2.

2. Initialize BLAKE3 working state:
   v[0..8)   = cv
   v[8..16)  = IV[0..8)

3. Run 7 BLAKE3 rounds with MSG_SCHEDULE from Section 3.4.

4. Fold the upper half of the BLAKE3 working state into the lower half:
   cv_new[i] = v'[i] ^ v'[i+8]    for i in 0..8

5. Apply the BlakeG 252-bit subspace mask (Section 4.2) to the odd `u32` lanes
   of the folded chaining value:
   cv_new[1] &= 0x7fff_ffff
   cv_new[3] &= 0x7fff_ffff
   cv_new[5] &= 0x7fff_ffff
   cv_new[7] &= 0x7fff_ffff

6. Return cv_new. Each pair `(cv_new[2t], cv_new[2t+1])` becomes one output Felt
   via `pack_masked` (Section 4.2); the masking step above ensures the resulting
   Felts are canonical in Goldilocks.
```

### 4.4 Initialization and domain binding

Eidos binds domain and length information once, into the initial chaining value `cv_0`, using the four-lane tag `[frame, selector, param0, param1]` specified in the domain-separation RFC, `eidos-domain-separation.md`. The `frame` lane carries the input length, `selector` and the two `param` lanes carry the registered domain, and each lane sits in the low half of a packed felt with a fixed BLAKE3 IV word in the high half, so `cv_0` stays in the 252-bit subspace and canonical in `F_M`. Each masked folded output then becomes the next `cv`.

```text
cv_0 = [
    pack(frame,    IV[1] & 0x7fff_ffff),
    pack(selector, IV[3] & 0x7fff_ffff),
    pack(param0,   IV[5] & 0x7fff_ffff),
    pack(param1,   IV[7] & 0x7fff_ffff),
]
```

The RFC is authoritative for the tag layout, the `selector` encoding, the registry, and validation.

### 4.5 Cheap lane setting

Each nonzero `cv_0` lane is set by a single Felt addition into the low half of a base constant, since the high-half IV word leaves the low 32 bits zero and every tag lane is bounded by `2^32 - 1`. So the addition never carries into the high lane, and init costs only these few additions and no bitwise work.

### 4.6 Input encoding, padding, and iteration

Eidos takes felt input (`hash_elements*`, `merge*`) or byte input (`hash`). Each is packed into compression blocks, and the final block is zero-padded to the full width:

- Felt input: 8 felts per block, padded with `Felt::ZERO`. Each block felt is decomposed into two `u32` lanes via Section 4.2.
- Byte input: 64 bytes per block, padded with `0u8`, then read as 16 little-endian `u32` words:

  ```text
  m[k] = bytes[4k] | (bytes[4k+1] << 8) | (bytes[4k+2] << 16) | (bytes[4k+3] << 24)
  ```

for `k in 0..16`.

The length is bound once in `cv_0` through the `frame` lane (Section 4.4), in felts for felt input and bytes for byte input; it must fit in `u32`, so a single call is at most `2^32 - 1` felts, or 4 GiB of bytes.

Empty input rule: if the input is empty, the hash performs one zero-block compression with `frame = 0`. There is no special zero-output shortcut. Empty input and single-zero input do not collide by padding alone because their `cv_0` values differ in the `frame` lane.

The iteration is:

```text
cv = cv_0(tag)
for each padded block:
    cv = BlakeG::compress(cv, block)
return pack_to_word(cv)
```

The zero padding is not self-delimiting. The length `n` in `cv_0` is what separates, for example, `[x]` from `[x, 0]` when both lead to related padded block contents.

### 4.7 Wide output

The shared BLAKE3 core computes two 8-word halves:

```text
low[i]  = v'[i]   ^ v'[i+8]
high[i] = v'[i+8] ^ h[i]
```

The hash uses only `low`, masked and packed into the 4-Felt digest. The AEAD (Section 7) uses the full raw 16-`u32` output `low || high`, unmasked, as its keystream. A felt-packed form of `high` is also definable, masking its odd lanes by the same BlakeG convention and packing into 4 more Felts:

```text
bcompress_wide(cv: Felt^4, block: Felt^8) -> (digest: Felt^4, wide: Felt^4)
```

This is BlakeG wide output, not standard BLAKE3's seekable XOF. BLAKE3's XOF runs its own output-block counter and flags, whereas BlakeG's wide output is just the second half already computed by one compression.

Exposing `high` changes nothing for the hash, which digests `low` only. For the AEAD, confidentiality rests on the raw 16-`u32` output being pseudorandom when the block holds a secret, the main open AEAD assumption (Section 7), in the same family as BLAKE3's XOF security.

---

## 5. Security claims

### 5.1 Concrete bounds

- **Collision resistance: 2^126 operations**
- **Preimage resistance: 2^252 operations**

These assume BLAKE3's 7-round core, which BlakeG uses unchanged (Section 3), so BLAKE3's round-count security argument for its 128-bit target carries over directly; the 2-bit reduction to 126-bit collision security is the output mask (Section 5.2), not the round count. The claims cover compression-mode use; exposing a bare permutation without the BLAKE3 compression-output wiring would need separate analysis.

### 5.2 Why 126 / 252

Each digest Felt holds `32 + 31 = 63` bits under the BlakeG packing convention. The digest is `Word = [Felt; 4]`:

- Total digest entropy: `4 * 63 = 252` bits.
- Birthday-bound collision security: `floor(252 / 2) = 126` bits.
- Preimage security: 252 bits.

The 2-bit gap relative to BLAKE3's 128-bit collision claim follows from the chosen output finalizer. The digest loses 4 bits of state relative to BLAKE3's 256-bit chaining value, one mask bit per odd lane; the birthday bound halves that loss, giving the 2-bit collision-security gap from 128 to 126. Section 5.4 specifies the finalizer and records the alternative-finalizer question.

### 5.3 Indifferentiability model

Eidos's iteration is a length-injecting prefix-free Merkle-Damgard variant. The total length `n` is bound at init, and padding is deterministic from `n`, so every input length corresponds to a distinct initial chaining value. Inputs of the same length are pairwise non-prefix-comparable unless they are identical, so distinct inputs cannot share an iteration prefix solely because one is a strict prefix of the other.

This is the prefix-free property used by Coron, Dodis, Malinaud, and Puniya, *Merkle-Damgard Revisited: how to Construct a Hash Function* (CRYPTO 2005), when the underlying compression function is modeled as ideal.

The security bound matches the digest's collision security: 126 bits.

Length-extension attacks are blocked in the Eidos hash: extending a digest by `k` blocks would require the hash under a tag with length `n + k`, while the observed digest was produced under a tag with length `n`. The returned digest is not a valid intermediate chaining value for the longer hash call.

### 5.4 Output finalizer

BlakeG applies a fixed output finalizer to the raw BLAKE3 compression output: the high-bit mask on odd `u32` lanes, defined in Section 4.2 and Section 4.3. This mask is the normative finalizer for this specification; the entropy it costs is accounted for in Section 5.2.

It places each output Felt in the subspace `S = [0, 2^63) subset F_M`, so a digest lives in `S^4`, a proper subset of `F_M^4`. A consequence is that BlakeG outputs cannot be used directly as uniform full-field masks for CTR encryption over arbitrary Goldilocks Felts (see Section 7.2); Section 7 shows how the AEAD avoids needing a different finalizer, by XORing the raw `u32` output rather than masking in the field.

Implementation note: any implementation that witnesses Felts as `u32` limbs must enforce the canonical Felt decomposition from Section 4.2. The mechanism is implementation-specific and belongs in the relevant AIR or circuit specification.

#### Open question: alternative finalizers

Whether a different output finalization could close the 2-bit collision-security gap (lifting digest entropy from `252` to `256` and collision security from `126` to `128`) is an open research question, analyzed in a separate finalizer research note.

---

## 6. Design rationale

Every BlakeG-mode choice serves one goal: a minimal steady-state VM loop. Standard BLAKE3 feeds per-call parameters (`counter`, `block_len`, `flags`) into `v[12..16)`, but the only stream-wide information Eidos binds, its domain tag and length, is fixed for the whole call, so it goes into `cv_0` once (Section 4.4) and `v[12..16)` is filled with the remaining IV words `IV[4..8)` (Section 3.1). The compression interface is then `(cv, block)` only (Section 4.3), keeping the steady loop minimal (Section 4.1). Byte and felt inputs are distinguished by registered domain, not a lane in `cv_0` (domain-separation RFC).

Two consequences worth stating:

- `v[8..16)` is the full BLAKE3 IV `IV[0..8)`, not zero, so BlakeG stays a faithful BLAKE3 mode.
- The chiplet is not BlakeG-only: future sibling operations may add stack inputs and selector-gated wiring for other modes (Section 8).

### 6.1 MASM call pattern

The init prologue builds `cv_0` from the tag by adding each tag lane into the low half of its base constant (Section 4.4), at most four Felt additions.

```text
# Init prologue: build cv_0 from the domain tag (Section 4.4)

# Steady-state loop
repeat.NUM_BLOCKS
    adv_pipe      # load next 8-Felt block into the block window
    bcompress     # current implementations may spell this hperm
end
```

The exact stack placement is an implementation detail; the normative cost shape is a few Felt additions at init, no per-block parameter pushes, and one compression call per block.

---

## 7. AEAD

Eidos provides an Encrypt-then-MAC AEAD. The plaintext is a sequence of field elements, but encryption does not mask in the field. Each plaintext felt is split into its two `u32` limbs and XORed with a CTR keystream, so the ciphertext is a sequence of `u32` limbs, twice the felt count, and a Wegman-Carter-Shoup tag authenticates that ciphertext. No secret is ever the chaining value, since every secret enters the block input of a compression whose chaining value is a public tag, so attacker-controlled data stays in the chosen-message regime of the 7-round core (Section 5.1).

### 7.1 Session key derivation

A secret key `K` and a per-encryption nonce `Nonce`, each 4 Felts, seed the session via two domain-separated derivations:

```text
K_ctr = BlakeG::compress(Init(AEAD_CTR_DOMAIN, frame=0), [K(4), Nonce(4)])
K_mac = BlakeG::compress(Init(AEAD_MAC_DOMAIN, frame=0), [K(4), Nonce(4)])
```

The 8-Felt input is fixed, so `frame = 0` (Section 4.4). The distinct domains keep `K_ctr` and `K_mac` independent under BlakeG's PRF security. `K_mac` is read as two `F_{M^2}` elements `(r, s)` for the tag (Section 7.3). Each `(K, Nonce)` pair MUST be used once: security needs Nonce uniqueness, not unpredictability, so a monotonic counter or a random Nonce both work, and with 4 Felts random collisions are negligible.

### 7.2 Keystream

The keystream is a CTR-mode prefix-key PRF. For block `i`:

```text
keystream_i  = wide_output(cv    = Init(AEAD_KEYSTREAM_DOMAIN, frame=0),
                           block = [K_ctr(4), counter_i(1), padding(3)])
               // raw 16 u32, low || high, unmasked (Section 4.7)
ciphertext_i = (plaintext_i split into u32 limbs) XOR keystream_i
```

The keystream runs under its own public tag, `AEAD_KEYSTREAM_DOMAIN`, so it is domain-separated from the key derivations (Section 7.1) and independent of them. The secret `K_ctr` sits in the block input, not the chaining value, so no keyed IV is needed. The full 16-`u32` output `low || high` is used unmasked, so one compression covers 8 plaintext Felts and yields 16 `u32` ciphertext limbs, a 2x expansion. Decryption recomputes the keystream, XORs again, and recombines limb pairs into Felts. The counter is a `u32`, giving up to `2^32` blocks per `(K, Nonce)`, and encryption MUST abort on counter exhaustion.

XOR over limbs is what lets the keystream avoid a full-field requirement. The masked BlakeG digest lives in the subspace `S = [0, 2^63)`, so a field-additive mask `c = m + k mod M` is not IND-CPA secure: with `m = 0` the ciphertext is always in `S`, whereas `m = 2^63` leaves `S` except with probability about `2^-31`, distinguishing the two. XOR needs only that the keystream bits are pseudorandom. Confidentiality therefore rests on the raw 16-`u32` output being pseudorandom when the block holds a secret, the wide-output property of Section 4.7, in the same family as BLAKE3's XOF security.

### 7.3 Authentication

The tag authenticates the ciphertext (Encrypt-then-MAC), the generically secure composition that needs no privacy property of the MAC. It is a Wegman-Carter-Shoup polynomial MAC in `F_{M^2}`, with `K_mac = (r, s)`:

```text
mac_input = nonce(4) || AD(...) || ciphertext(...) || ad_len(1) || ct_len(1)
            // read as F_{M^2} coefficients m_i, padded to even length L
T    = L / 2
P(x) = sum_{i=0}^{T-1} m_i * x^{T-1-i}
tag  = P(r) + s in F_{M^2}
```

The length fields `ad_len` and `ct_len` bind the AD and ciphertext boundary. The tag is 2 Felts. Forgery per attempt is about `T / 2^126`, since `K_mac` comes from the masked BlakeG output, so `r` and `s` carry 126-bit support rather than full `F_{M^2}`. The bound degrades with length:

| Authenticated payload | L (Felts) | T (coefficients) | Per-attempt forgery |
|---|---:|---:|---:|
| 1 KB | 2^7 | 2^6 | about 2^-120 |
| 1 MB | 2^17 | 2^16 | about 2^-110 |
| 1 GB | 2^27 | 2^26 | about 2^-100 |
| 256 GB | 2^35 | 2^34 | about 2^-92 |

so the spec MUST define `MAX_AEAD_AUTHENTICATED_LEN`. Nonce uniqueness is required, since a repeated nonce repeats both `K_ctr`, breaking keystream secrecy, and the one-time mask `s`, breaking the forgery bound. Decryption recomputes the tag, compares in constant time, and decrypts only on a match.

### 7.4 Future option: authenticating the plaintext

The one open variant is MACing the plaintext rather than the ciphertext. It halves the MAC work, since the plaintext is 8 Felts per block against the 16-Felt expanded ciphertext, but it is the Encrypt-and-MAC paradigm, which does not generically preserve confidentiality, since a MAC guarantees unforgeability and not privacy of its input. A one-time-masked WC tag can be made tag-private under strict nonce uniqueness, following the N1 composition of Namprempre-Rogaway-Shrimpton (EUROCRYPT 2014), but that is an extra assumption Encrypt-then-MAC does not need. Adopting it would require verifying the tag over recovered plaintext before exposing that plaintext, and restating the length and forgery accounting.

### 7.5 Limitations

Associated data is currently empty-AD only. The counter range is at most `2^32` blocks per nonce. The ciphertext is 2x expanded into `u32` limbs.

---

## 8. Forward compatibility with standard BLAKE3 compression

This section is non-normative. It records what this spec deliberately leaves open.

BlakeG and standard BLAKE3 compression share:

- the same 7-round ARX core;
- the same IV constants;
- the same BLAKE3 message schedule;
- the same low/high output equations.

They differ in mode wiring:

| | BlakeG mode | Future standard-BLAKE3-compression mode |
|---|---|---|
| `v[12..16)` | fixed `[IV[4], IV[5], IV[6], IV[7]]` | runtime `[counter_lo, counter_hi, block_len, flags]` |
| initial `h` | Eidos `cv_0` with domain and length injection | caller-provided BLAKE3 chaining value; full hash/chunk/key rules live outside this compression op |
| output | BlakeG odd-lane mask, then two-lane Felt packing | raw BLAKE3 `u32` lanes, no BlakeG mask |
| public operation | `bcompress` style `(cv, block)`; current VM implementations may reuse the `hperm` opcode shape | sibling operation with extra parameter inputs |

Adding such a mode should not require changing the core round function, message schedule, or round count. It would require mode selection, runtime inputs for `v[12..16)`, and different output packing. This spec therefore scopes BlakeG-specific constraints to BlakeG mode and avoids treating the chiplet as BlakeG-only.

This future mode would be a standard BLAKE3 compression operation, not automatically a full standard BLAKE3 hash implementation. The full hash also includes chunking, tree reduction, flags, and output generation rules.

---

## 9. References

### Primary BLAKE3 sources

- O'Connor, J., Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z. *BLAKE3: one function, fast everywhere.* BLAKE3 specification. <https://github.com/BLAKE3-team/BLAKE3-specs>
- BLAKE3 team. *BLAKE3 official implementation.* <https://github.com/BLAKE3-team/BLAKE3>

### Cryptanalysis and design literature

The BLAKE3 sources above are normative for the round function, message schedule, and compression-output wiring inherited by BlakeG. The works below cover the analytical and constructional foundations referenced in this spec.

- Aumasson, J.-P. *Too Much Crypto.* IACR ePrint 2019/1492. (Argument for 7-round security margin.)
- Coron, J.-S., Dodis, Y., Malinaud, C., Puniya, P. *Merkle-Damgard Revisited: how to Construct a Hash Function.* CRYPTO 2005. (Indifferentiability framework used in Section 5.3.)
- Bernstein, D. J. *The Poly1305-AES MAC.* FSE 2005. (Wegman-Carter-Shoup polynomial-MAC construction; pattern for the MAC in Section 7.3.)
- Bellare, M., Namprempre, C. *Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm.* ASIACRYPT 2000. (Encrypt-then-MAC composition theorem; foundation for Section 7's IND-CCA argument.)
- Namprempre, C., Rogaway, P., Shrimpton, T. *Reconsidering generic composition.* EUROCRYPT 2014. IACR ePrint 2014/206. (Nonce-based AE composition; N1 covers MACs over `(nonce, AD, plaintext)` under a PRF-style MAC assumption.)

---

## Appendix A - Notation glossary

- `Felt` - element of the Goldilocks field `F_M`.
- `M` - Goldilocks field modulus, `M = 2^64 - 2^32 + 1`.
- `Word` - `[Felt; 4]`, Eidos's digest type.
- `h` / `cv` - chaining value, `[u32; 8]` inside the BLAKE3 core and `[Felt; 4]` at the BlakeG boundary.
- `m` / `block` - the 512-bit block, `[u32; 16]` inside the BLAKE3 core and `[Felt; 8]` for BlakeG felt input.
- `p` - the four BLAKE3 state initialization words placed into `v[12..16)`; not the field modulus.
- `v` - 16-word working state inside the compression function.
- `IV[i]` - i-th BLAKE3 IV word.
- `frame` - the hash-owned length lane of the domain tag; see the domain-separation RFC.
- `selector`, `param0`, `param1` - the protocol-owned lanes of the domain tag.
- `n` - input length, in Felts for felt input and bytes for byte input; carried in `frame`.
- `domain` - the registered domain identifying a commitment; encoded in `selector`.
- `adv_pipe` - Miden MASM instruction that pops two words, i.e. 8 Felts, from the advice stack, overwrites the top two stack words, writes them to memory at the current pointer, and advances the pointer. In the BlakeG loop, this supplies the next 8-Felt compression block.
- `hperm` - current Miden hash-permutation opcode shape, inherited from the older sponge/permutation interface. It may be the implementation spelling during migration, but it is not the BlakeG primitive name.
- `bcompress` - BlakeG compression operation over `(cv: Felt^4, block: Felt^8) -> Felt^4`.

