# Eidos — Design and Specification

## 1. Overview

Eidos is a cryptographic hash function with two layers:

- **BlakeG** — a Goldilocks-tailored Blake2s-style compression function. The cryptographically auditable core. Knows nothing about the Miden VM.
- **Eidos** — a hash function built on BlakeG. Owns padding, domain separation, mode bits, and the public API. Designed for the Miden VM's chiplet model.

Output: `Word = [Felt; 4]` (4 Goldilocks felts).

Security target:
- **Collision resistance: 126 bits** (birthday bound)
- **Preimage resistance: 252 bits**

The 2-bit gap below the BLAKE3-standard 128-bit collision target comes from the Goldilocks felt-packing convention, not from the hash construction itself. See §5.

---

## 2. Architecture

### 2.1 Two-stream rationale

The work splits cleanly along the field/VM boundary:

| | BlakeG (Stream 1) | Eidos (Stream 2) |
|---|---|---|
| Concern | Field-tailored cryptographic primitive | Padding, framing, domain separation, public API |
| Reusability | Any Goldilocks project | Specific to Miden's framing choices |
| Audit surface | Compression-function cryptanalysis | Padding/domain-separation correctness, length binding |

This separation makes each layer's design rationale independently reviewable. The compression-function literature (Blake2/3 cryptanalysis) applies entirely to BlakeG. The framing literature (sponge/duplex/HAIFA design analysis) applies entirely to Eidos.

### 2.2 Module layout

```
miden-crypto/src/hash/eidos/
  mod.rs           public re-exports: BlakeG, Eidos
  primitive.rs     BlakeG: Blake2s compression over Goldilocks
  framing.rs       Eidos: public API + framing constants
  SPEC.md          this document
  tests.rs         tests for both layers
```

### 2.3 Type surface

```rust
// Stream 1 — field layer
pub struct BlakeG;
impl BlakeG {
    pub const ROUNDS: usize = 7;
    pub const STATE_WORDS: usize = 8;       // u32 lanes
    pub const BLOCK_WORDS: usize = 16;       // u32 lanes per block
    pub fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8];
}

// Stream 2 — VM layer
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

---

## 3. BlakeG — Field-layer primitive

### 3.1 Underlying construction

BlakeG is the Blake2s compression function with two modifications:

1. **7 rounds** instead of standard 10 (justification in §3.5).
2. **No HAIFA per-block parameters** (no counter `t`, no finalization flag `f`). The working state's upper half (`v[8..16]`) is set directly to `IV[0..8]` without XORing `t` or `f`.

Otherwise, BlakeG preserves Blake2s's structure faithfully:
- 16-word working state `v` (u32 each)
- Davies–Meyer feed-forward to produce the new chaining value
- Standard Blake2s ARX round function (G mixing function, column + diagonal layout)
- Standard Blake2s `SIGMA` schedule (truncated to 7 rounds)
- Standard Blake2s IV constants

### 3.2 Goldilocks packing convention

Blake2s natively operates on `u32` lanes. The Miden Goldilocks field has prime modulus `p = 2^64 − 2^32 + 1`. To represent the 8-word chaining state in 4 Goldilocks felts:

```
pack(lo: u32, hi: u32) -> Felt
    = Felt::from_u64(((hi & 0x7fff_ffff) as u64) << 32 | lo as u64)
```

Why mask the top bit of the high lane: a fully-utilized 64-bit value would exceed the Goldilocks prime. Masking the top bit forces every packed value into the canonical range `[0, 2^63)`, which is unambiguously representable as a Felt.

Cost of this convention: **4 bits of state entropy lost** (one bit per odd lane in a 4-felt packed state). This propagates through to the digest entropy (§5).

The compression function operates entirely on `[u32; 8]` chaining values; the packing convention applies only at the boundary where the chaining state crosses into Felt-typed APIs (i.e., in the Eidos layer). BlakeG itself is `[u32; 8]`-typed throughout.

### 3.3 Compression signature

```rust
pub fn compress(cv: [u32; 8], block: [u32; 16]) -> [u32; 8]
```

**Input invariant**: the top bit of `cv[1], cv[3], cv[5], cv[7]` must be zero (i.e., `cv` lives in a 252-bit subspace of `[u32; 8]`). This invariant is established by Eidos's init (§4.2) and preserved by `compress`'s output mask below.

Implementation:

```
1. Initialize working state v: [u32; 16]
   v[0..8]   = cv
   v[8..16]  = IV[0..8]              // standard Blake2s IV, no t/f XORed in

2. Run 7 rounds of the round function on v (with message schedule from `block`)

3. Apply Davies–Meyer feed-forward:
   cv_new[i] = cv[i] ^ v[i] ^ v[i+8]   for i in 0..8

4. Apply 252-bit subspace mask (preserves the input invariant on output):
   cv_new[1] &= 0x7fff_ffff
   cv_new[3] &= 0x7fff_ffff
   cv_new[5] &= 0x7fff_ffff
   cv_new[7] &= 0x7fff_ffff

5. Return cv_new
```

Standard Blake2s `IV[0..8]`:
```
IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]
```

### 3.4 Why HAIFA per-block parameters are dropped

Standard Blake2s uses HAIFA: each compression call takes a counter `t` and a finalization flag `f`, XORed into `v[12..16]`. These provide:
- per-block positional uniqueness (via `t`)
- finalization separation, blocking length-extension (via `f`)

In Eidos, length is bound at init (§4.2). A hasher iteration that processes `n` units is a fundamentally different function from one that processes `n′` units, because their `h_0` differs. This subsumes both HAIFA properties:
- Positional uniqueness: the chain `h_0, h_1, …, h_k` is uniquely keyed by `n` at `h_0`.
- Length-extension resistance: extending a hash requires producing `Init(domain, n+k)` output, which the original hasher did not produce.

Dropping per-block params simplifies the chiplet and the MASM-side op signature.

**Trade-off acknowledged:** this design forecloses streaming APIs where the total length is unknown until finalize. Streaming would require re-introducing per-block length binding.

### 3.5 Round count: 7 rounds

Justification chain:

- **BLAKE3 precedent.** BLAKE3 (Aumasson, Neves, O'Connor, Wilcox-O'Hearn) uses 7 rounds with a 128-bit security target, defended in §5.3 of the BLAKE3 specification.
- **Too Much Crypto** (Aumasson, IACR ePrint 2019/1492) explicitly proposes BLAKE2s 10→7 as part of a broader argument that mature symmetric primitives are over-rounded by historical convention.
- **Six-year retrospective** (Aumasson, 2025) confirms no cryptanalytic progress since the TMC proposal: best practical attack remains at 2.5 rounds; best theoretical at 7.5 rounds (boomerang, complexity 2^184; Hao 2014, IACR ePrint 2014/1012); the 7-round level has not been weakened.
- **ChaCha permutation distinguishers** at 7 rounds reach complexity 2^207 (Dey, Garai, Sarkar, *Scientific Reports* 2023). These apply to the bare permutation and **do not transfer to compression mode** with fixed IV. BlakeG uses compression mode.

**Important caveat for downstream users:** BLAKE3's 7-round vouching covers compression-mode use only. If a future variant exposes the bare permutation, its round count requires its own analysis. See §7.3.

---

## 4. Eidos — VM-layer hash

### 4.1 Public API

Mirrors Poseidon2 (`miden-crypto/src/hash/algebraic_sponge/poseidon2/mod.rs`):

```rust
impl Eidos {
    pub fn hash(bytes: &[u8]) -> Word;
    pub fn hash_elements<E: BasedVectorSpace<Felt>>(elements: &[E]) -> Word;
    pub fn hash_elements_in_domain<E: BasedVectorSpace<Felt>>(elements: &[E], domain: Felt) -> Word;
    pub fn merge(values: &[Word; 2]) -> Word;
    pub fn merge_many(values: &[Word]) -> Word;
    pub fn merge_in_domain(values: &[Word; 2], domain: Felt) -> Word;
}
```

`merge`, `merge_many`, `merge_in_domain` are wrappers over `hash_elements*` on the concatenated felt content of the input words.

### 4.2 Init chaining word

The initial chaining value `cv_0` is constructed at the packed-Felt level — that is, as 4 Goldilocks felts that, when unpacked to 8 u32 lanes, give the standard Blake2s IV with three modifications: the parameter-block XOR into `h[0]`, the `domain + MODE_BIT` injected into `h[4]`, and the length `n` injected into `h[6]`.

The packed-Felt formulation is the load-bearing one (it's what the MASM side will compute):

```
cv_0 (as 4 Felts) = [
    BASE0,
    BASE1,
    BASE2 + (domain + MODE_BIT_VALUE),
    BASE3 + n,
]
```

Where:

| Constant | Value | Meaning |
|---|---|---|
| `BASE0` | `0x3b67_ae85_6b08_e647` | `pack(IV0 ^ PARAM_WORD_0, IV1)` |
| `BASE1` | `0x254f_f53a_3c6e_f372` | `pack(IV2, IV3)` |
| `BASE2` | `0x1b05_688c_0000_0000` | `pack(0, IV5)` — low 32 bits reserved for `domain + MODE_BIT` |
| `BASE3` | `0x5be0_cd19_0000_0000` | `pack(0, IV7)` — low 32 bits reserved for `n` |
| `PARAM_WORD_0` | `0x0101_0020` | Standard Blake2s parameter word for unkeyed-256 |
| `MODE_BIT` | `1 << 31 = 0x8000_0000` | Felt-mode = 0; byte-mode = `MODE_BIT` |


**Why `+` and not `^` for injection.** The init injects `domain` and `n` via Felt addition (`BASE2 + (domain + MODE_BIT)`, `BASE3 + n`), not via XOR. Two reasons:

1. **MASM cost.** Felt addition is a single field-op; `+` costs one cycle on the op stack. A bitwise XOR of two Felts is *not* a Felt-level op — Felts are field elements, not u32 vectors. Doing XOR in MASM requires `u32split` to decompose, `u32xor` (lookup-backed) on the lanes, then recompose — roughly 3-5× the cost per injection.
2. **No carry into protected lanes.** The low 32 bits of `BASE2` and `BASE3` are zero (by the `pack(0, IV[odd])` construction). `domain + MODE_BIT < 2^32`; `n ≤ u32::MAX < 2^32`. Adding values smaller than `2^32` to a slot whose low 32 bits are zero never carries into the high 32 bits, so the masked IV in the high half stays intact.

This is the principal reason our init formula differs from the natural Blake2s expression of `h[0] ^= PARAM_WORD_0; h[6] ^= domain; h[7] ^= padding`. Both produce a "modified IV"; ours is just the form that's cheap to compute on the MASM op stack.

Equivalently, the unpacked u32 chaining state at init is:

```
h[0] = IV[0] ^ PARAM_WORD_0
h[1] = IV[1] & 0x7fff_ffff       // odd lane masked
h[2] = IV[2]
h[3] = IV[3] & 0x7fff_ffff       // odd lane masked
h[4] = domain + MODE_BIT_VALUE
h[5] = IV[5] & 0x7fff_ffff       // odd lane masked
h[6] = n
h[7] = IV[7] & 0x7fff_ffff       // odd lane masked
```

The masked odd lanes are an unavoidable consequence of the packed-Felt convention (§3.2). They're forced to zero throughout the iteration; they don't create exploitable structure (they're constant, not adversary-controlled).

### 4.3 Mode bit — felt mode vs byte mode

Eidos has two operating modes, distinguished by the top bit of the `domain` slot in the init:

| Mode | Caller API | Block semantics | `MODE_BIT_VALUE` in init | `n` semantics |
|---|---|---|---|---|
| Felt mode | `hash_elements*`, `merge*` | 8 felts per block (each felt as 2 u32 lanes) | `0` | number of input felts |
| Byte mode | `hash` | 64 bytes per block (16 u32 lanes, little-endian) | `MODE_BIT = 0x8000_0000` | number of input bytes |

This forces felt-mode and byte-mode hashes to diverge at the **first compression call**, even when their u32 block contents happen to coincide.

User domain space is reduced to **31 bits**: `domain < 2^31`. The top bit is reserved for mode separation. This is asserted at the API boundary; out-of-range domains are a programming error.

### 4.4 Length binding

`n` (in slot 3) carries:
- the number of input felts in felt mode
- the number of input bytes in byte mode

Asserted at the API boundary: `n` must fit in `u32`. For felt mode this is effectively unbounded for any realistic input; for byte mode, the limit is 4 GiB per hash.

### 4.5 Padding

Both modes pad the final block with zeros to the full block width:

- Felt mode: pad with `Felt::ZERO` until block contains 8 felts.
- Byte mode: pad with `0u8` until block contains 64 bytes.

**Empty input rule:** if the input is empty (0 felts or 0 bytes), the hash performs **one zero-block compression with `n = 0`**. This unifies the semantics across both modes — there's no special "return zero" shortcut.

The zero-padding is non-invertible (a felt input ending in `Felt::ZERO` looks the same as a shorter felt input padded to the next block boundary, as far as the block contents go). The length `n` in init disambiguates these cases. Without `n` in init, padding-collision attacks would be possible.

### 4.6 Domain separation

Three independent bindings, all in the init chaining word:

| Separation | Mechanism | Slot |
|---|---|---|
| Felt-mode vs byte-mode | `MODE_BIT` (top bit of slot 2 low lane) | 2 |
| Different user domains within a mode | `domain` (low 31 bits of slot 2 low lane) | 2 |
| Different input lengths | `n` (slot 3 low lane) | 3 |

Any difference along any of these axes diverts the iteration at the first compression. The chaining states for, say, `(felt-mode, domain=5, n=3)` and `(byte-mode, domain=5, n=3)` are distinct from `cv_0` onward, propagating to entirely uncorrelated digests.

### 4.7 Compression iteration

```
cv = cv_0
for each padded block in input:
    cv = BlakeG::compress(cv, block)
return pack_to_word(cv)
```

`pack_to_word` applies the Goldilocks packing convention (§3.2) to convert the final 8-word chaining state into a `Word = [Felt; 4]`.

---

## 5. Security claims

### 5.1 Concrete bounds

- **Collision resistance: 2^126 operations**
- **Preimage resistance: 2^252 operations**

### 5.2 Why 126 / 252

Each digest felt holds `32 + 31 = 63` bits of entropy under the Goldilocks packing convention (§3.2). The digest is `Word = [Felt; 4]`:

- Total digest entropy: `4 × 63 = 252` bits.
- Birthday-bound collision: `⌊252 / 2⌋ = 126` bits.
- Preimage: `252` bits.

The 2-bit gap relative to BLAKE3's 128-bit claim is purely a packing artifact. The compression function itself provides BLAKE3-level security; the digest output simply has fewer bits to work with because of how Goldilocks felts represent state.

### 5.3 Indifferentiability

Eidos's iteration is a **length-injecting prefix-free Merkle–Damgård variant**. Because the total length `n` is bound at init and padding is deterministic from `n`, every input length corresponds to a distinct hash function (effectively keyed by length, with prefix-freeness following directly).

This satisfies the prefix-free property required by **Coron, Dodis, Malinaud, Puniya** (*Merkle-Damgård Revisited: how to Construct a Hash Function*, CRYPTO 2005), which proves that prefix-free MD constructions are indifferentiable from a random oracle when the underlying compression function is treated as an ideal compression.

The security bound matches the digest's collision security: 126 bits (§5.1).

**Length-extension attacks** are blocked: extending a hash by `k` blocks would require producing output under `Init(domain, n+k)`, which a hasher operating with `Init(domain, n)` did not produce. The returned digest is not a valid intermediate chaining value for any longer iteration.

---

## 6. Design rationale

### 6.1 Why `n` in init instead of HAIFA per-block params

See §3.4. Summary: HAIFA's per-block counter and finalization flag exist to provide positional uniqueness and length-extension resistance. With total length committed at init, both properties follow from the init binding alone, and then per-block params can be dropped.

### 6.2 Why one MODE_BIT in slot 2 instead of a separate mode slot

Domain space reduction from `2^32` to `2^31` is modest. Adding a separate slot for the mode bit would either consume one of the four init slots entirely which seems wasteful. This decision is not a hard one though.

### 6.3 Compression op signature: `compress(cv, block)`

The MASM-side chiplet op (`bcompress`) takes `(cv, block)` only — no `t`, no `f`. This:
- Matches BlakeG's pure cryptographic signature.
- Works seamlessly with Miden VM stack patterns (`mem_stream`, `adv_pipe` overwrite top-8 stack slots; persistent state lives at slots 8..12).
- Avoids carrying additional params across iterations and hence eases the burden on the op stack.

The chiplet's underlying 7-round ARX core would also support a "permutation" output wiring (without feed-forward XOR), enabling future ops like `bperm` for block-cipher-mode use cases. Though this would require a deeper cryptographic analysis.

---

## 7. AEAD direction (future work)

Eidos AEAD is a separate effort, deferred until the hash function ships. This section sketches two viable construction families and the trade-offs between them.

Both options share an **Encrypt-then-MAC** architecture:
- **Encryption**: CTR mode using `BlakeG::compress` as a PRF.
- **Authentication**: a tag computed over `(nonce || AD || ciphertext || lengths)` using either `Eidos::hash` (Option A) or polynomial evaluation in F_p² (Option B).

Crucially, neither option exposes `BlakeG::compress` to chosen-key attacks. In Davies-Meyer terms, the chaining value (`cv`) acts as the cipher's key, and the block acts as the plaintext. In both options, the `cv` is always either a secret derived key (`K_ctr`, `K_mac`) or an accumulating hash state—never an attacker-controlled ciphertext. Because the attacker only ever controls the block input (the "message"), the construction remains strictly within the chosen-message threat model, preserving the 7-round security guarantees established in §3.5.

### 7.1 Common architecture

#### 7.1.1 Session key derivation

A single secret key `K` and a per-encryption nonce `Nonce` (each 4 felts) seed the session via two domain-separated derivations:

```text
K_ctr = BlakeG::compress(Init(AEAD_CTR_DOMAIN, n=8), [K(4), Nonce(4)])    // 4 felts
K_mac = BlakeG::compress(Init(AEAD_MAC_DOMAIN, n=8), [K(4), Nonce(4)])    // 4 felts
```

Both are 4-felt PRF keys, derived once per session and stored in memory (read-only inside the encryption / authentication loops). Domain separation between the derivations guarantees `K_ctr` and `K_mac` are independent under PRF security of `BlakeG::compress`.

(Option B reinterprets `K_mac` as 4 felts that pack two F_p² elements `r` and `s` for the Wegman-Carter-Shoup construction — see §7.3.)

#### 7.1.2 CTR encryption

For each 8-felt plaintext block at index `i` (counter starting at 0, advancing by 2 per block):

```text
keystream_lo = BlakeG::compress(K_ctr, [counter=2i,   padding(7)])    // 4 felts
keystream_hi = BlakeG::compress(K_ctr, [counter=2i+1, padding(7)])    // 4 felts
keystream    = keystream_lo || keystream_hi                           // 8 felts
ciphertext_i = plaintext_i + keystream                                // 8 felts 
```

Decryption is identical with `−` instead of `+`:

```text
plaintext_i  = ciphertext_i − keystream
```

**The same `BlakeG::compress` calls are used for both encrypt and decrypt** — keystream generation is identical; only the keystream-combining sign flips. No inverse op is needed.

The counter is a 32-bit value held in a single Felt; this supports up to 2^31 blocks per session = 2^34 felts ≈ 128 GiB of plaintext per (K, Nonce) pair.

### 7.2 Option A: CTR + Hash MAC

#### 7.2.1 Construction

After CTR encryption, compute the tag by hashing the canonical authenticated input keyed with `K_mac`:

```text
mac_input = K_mac(4) || nonce(4) || AD(...) || ciphertext(...) || ad_len(1) || ct_len(1)
tag       = Eidos::hash_elements_in_domain(mac_input, AEAD_TAG_DOMAIN)
            // 4 felts (Word)
```

`K_mac` as a prefix turns `Eidos::hash` into a keyed hash. `nonce` is included redundantly but could be removed. `ad_len` and `ct_len` are the lengths in felts encoded as Felts each, preventing AD/ciphertext boundary-shifting attacks.

Decryption flow:
1. Recompute `tag'` from the received `(nonce, AD, ciphertext)` using the same procedure.
2. Constant-time compare `tag' == tag_received`. If unequal, **reject — do not decrypt.**
3. If equal, decrypt as in §7.1.2.

#### 7.2.2 Security

- **Confidentiality (IND-CPA)** from the PRF security of `BlakeG::compress` keying CTR mode.
- **Integrity (INT-CTXT)** from the unforgeability (SUF-CMA) of the length-bound, keyed `Eidos::hash`. Because the hash is prefix-free (via the injected length/finalization), the secret-prefix construction `Hash(K_mac || M)` acts as a secure PRF. The security against internal state collisions is 126 bits (the birthday bound on the 252-bit chaining value), flat across all message lengths — see §5.1.
- **Combined IND-CCA** via the standard Encrypt-then-MAC composition theorem (Bellare-Namprempre, Asiacrypt 2000).

**Architectural note on block alignment:** In felt-mode, a compression block is exactly 8 felts. Because the `mac_input` starts with `K_mac(4) || nonce(4)`, the entire first block is perfectly filled by the secret key and fixed nonce. The attacker-controlled input (AD and ciphertext) only begins in Block 2. This effectively upgrades the construction to a secret-IV MAC. The internal state after Block 1 is completely secret and fixed, thoroughly insulating the key material from chosen-message manipulation within the same block.

**Forgery probability:** Because `K_mac` is derived *per-nonce* (§7.1.1), it acts as a true one-time key. An attacker never sees more than a single valid MAC output for a given `K_mac`. Therefore, they cannot mount the $2^{126}$ chosen-message queries needed to find an internal state collision. If an attacker submits a forged ciphertext for an existing nonce, they are blindly guessing the 252-bit tag. The forgery probability per attempt is bounded by **$2^{-252}$**, regardless of message length.

#### 7.2.3 Throughput

Per 8-felt plaintext block we need 3 `bcompress` calls. Compare this to the Poseidon2-based AEAD construction which needs only 1 call to the Poseidon2 permutation.

### 7.3 Option B: CTR + Algebraic MAC (Blake-Poly)

#### 7.3.1 Construction

Encryption is identical to §7.1.2. Authentication uses Wegman-Carter-Shoup polynomial evaluation in F_p² (Bernstein, *The Poly1305-AES MAC*, FSE 2005) instead of hashing.

`K_mac` is interpreted as 4 felts holding two F_p² elements:

```text
K_mac = [r0, r1, s0, s1]
r = (r0, r1) ∈ F_p²    // polynomial evaluation point
s = (s0, s1) ∈ F_p²    // Wegman-Carter-Shoup masking term
```

The MAC input is encoded as a sequence of F_p² polynomial coefficients:

```text
mac_input_felts = nonce(4) || AD(...) || ciphertext(...) || ad_len(1) || ct_len(1)
                  // padded with Felt::ZERO to even total length L
M               = L / 2                                          // number of F_p² coefficients
m_i             = (mac_input_felts[2i], mac_input_felts[2i+1])  ∈ F_p²    for i in 0..M

P(x) = Σ_{i=0}^{M-1} m_i · x^{M-i}                              // polynomial of degree M in F_p²[x]

tag_raw = P(r) + s   ∈ F_p²
tag     = (tag_raw.0, tag_raw.1)   ∈ [Felt; 2]                  // 2-felt tag
```

Decryption: recompute tag, constant-time compare, then decrypt as in §7.1.2.

**Note on tag width**: the tag is 2 felts (≈ 128 bits), not 4 felts as in Option A. This matches Poly1305 / GMAC's 128-bit tag size and is sufficient for 128-bit forgery resistance. For API uniformity with Option A's `Word`-shaped tag, the implementation may pad with two `Felt::ZERO` (semantically irrelevant — security is in the 2 nonzero felts).

#### 7.3.2 Security

- **Confidentiality**: same as Option A — PRF security of CTR mode keyed by `K_ctr`.
- **Integrity**: forgery probability per attempt bounded by `M / 2^{126}`, where `M` is the number of polynomial coefficients in the MAC input. The denominator reflects the 126-bit entropy of the evaluation point `r` under the Goldilocks packing convention (each felt holds 63 bits of entropy; `r` comprises 2 felts), rather than the mathematical field size $|F_p²| \approx 2^{128}$.
- **Standard Wegman-Carter-Shoup analysis**; the `+ s` masking provides a one-time-MAC-style guarantee per session (per (K, Nonce) pair).

Forgery probability as a function of authenticated payload size (L = total felts in MAC input including AD, CT, nonce, lengths; M = L / 2 polynomial coefficients; bounding entropy at $2^{126}$; assuming 8 bytes per felt):

| Authenticated payload | L (felts) | M (coefficients) | Per-attempt forgery probability |
|---|---|---|---|
| 1 KB | 2^7 | 2^6 | ≈ 2^-120 |
| 1 MB | 2^17 | 2^16 | ≈ 2^-110 |
| 1 GB | 2^27 | 2^26 | ≈ 2^-100 |
| 256 GB | 2^35 | 2^34 | ≈ 2^-92 |

This degradation shape is identical to AES-GCM and ChaCha20-Poly1305 — both widely accepted in production protocols (TLS, Noise, IPsec). To enforce a strict security floor, the AEAD spec must define `MAX_AEAD_AUTHENTICATED_LEN`. For example, capping at 2^28 felts (≈ 2 GB) gives a floor of ≈ 2^-100 forgery probability per attempt; capping at 2^17 felts (≈ 1 MB) keeps the floor above 2^-110.

#### 7.3.3 Throughput

Per 8-felt plaintext block, 2 calls to `bcompress` are made during keystream generation and 1 `horner_eval_ext` during the MAC pass.

Option B trades **1 hash chiplet call per block** for **roughly identical MASM cycle cost** vs Option A. 

---

## 8. Length-binding constructions — design alternatives

Eidos's resistance to padding collisions and length-extension attacks (§5.4) requires binding the input length into the iteration. There are two natural ways to do this. They achieve the same security target via different placements of the length information.

### Construction 1 — Full-length init

The init chaining word encodes the full input length `n` in slot 3:

```
cv_0 = pack(BASE0, BASE1, BASE2 + (domain + mode), BASE3 + n)
```

Every distinct length yields a distinct init chaining value, propagating to uncorrelated iterations from the first compression onward.

- **Padding collisions**: blocked. Two messages of different lengths cannot share an init, regardless of whether their padded final blocks happen to coincide.
- **Length extension**: blocked. Computing `H(M || ext)` requires the iteration to start under `Init(domain, mode, |M|+|ext|)`, which is distinct from the `Init(domain, mode, |M|)` used to produce `H(M)`.

This is the construction described in §4.

### Construction 2 — Mod-rate init plus finalization step

The init chaining word encodes the residue `n_lo = n mod block_size` (block size in the mode's native units — `RATE` felts in felt mode, 64 bytes in byte mode) in slot 3:

```
cv_0 = pack(BASE0, BASE1, BASE2 + (domain + mode), BASE3 + n_lo)
```

A finalization domain separator is applied to the chaining value before the final compression of the iteration — for instance, adding a fixed nonzero constant to one cap lane:

```
cv_final_input = cv_chained + FINAL_FLAG_in_one_lane
```

The two halves of the binding work together:

- **Padding collisions**: blocked by `n_lo`. Two messages whose only difference is trailing zeros have different residues (one's last block is zero-padded, the other's isn't), so their inits differ.
- **Length extension**: blocked by finalization. The chained cv after the final compression includes the structural separator; an attacker holding `H(M)` cannot continue iterating without reproducing the un-finalized intermediate cv, which is one-way-protected by the compression function.

### Equivalence

Both constructions yield the same security claims (§5). The §5.4 indifferentiability argument applies to either: in Construction 1, the iteration is length-injecting via init; in Construction 2, it is length-injecting via the combination of init residue and a domain-separated final compression. Both produce prefix-free Merkle–Damgård variants in the sense of Coron, Dodis, Malinaud, Puniya (2005).

---

## 9. References

### Cryptanalysis literature

- Guo, J., Karpman, P., Nikolic, I., Wang, L., Wu, S. *Analysis of BLAKE2.* IACR ePrint 2013/467. <https://eprint.iacr.org/2013/467>
- Hao, Y. *The Boomerang Attacks on BLAKE and BLAKE2.* IACR ePrint 2014/1012. <https://eprint.iacr.org/2014/1012>
- Dey, S., Garai, H. K., Sarkar, S. *A new distinguishing attack on reduced round ChaCha permutation.* Scientific Reports, 2023. <https://www.nature.com/articles/s41598-023-39849-1>
- *On Improved Cryptanalytic Results against ChaCha for Reduced Rounds ≥ 7.* IACR ePrint 2025/428. <https://eprint.iacr.org/2025/428>

### Design

- Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z., Winnerlein, C. *BLAKE2: simpler, smaller, fast as MD5.* IACR ePrint 2013/322.
- O'Connor, J., Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z. *BLAKE3: one function, fast everywhere.* BLAKE3 specification. <https://github.com/BLAKE3-team/BLAKE3-specs>
- Aumasson, J.-P. *Too Much Crypto.* IACR ePrint 2019/1492. <https://eprint.iacr.org/2019/1492>
- Aumasson, J.-P. *6 years after Too Much Crypto.* 2025. <https://bfswa.substack.com/p/6-years-after-too-much-crypto>
- Reyhanitabar, R., Vaudenay, S., Vizár, D. *OMD: A Compression Function Mode of Operation for Authenticated Encryption.* CAESAR submission, 2014.

---

## Appendix A — Notation glossary

- `cv` — chaining value (`[u32; 8]` in BlakeG; `[Felt; 4]` after packing).
- `block` — input block to compression (`[u32; 16]`).
- `v` — working state inside compression (`[u32; 16]`).
- `Felt` — Goldilocks field element (modulus `2^64 − 2^32 + 1`).
- `Word` — `[Felt; 4]`. Eidos's digest type.
- `IV[i]` — i-th word of standard Blake2s IV.
- `BASE0..BASE3` — packed-Felt init constants (§4.2).
- `MODE_BIT` — `1 << 31`. Felt mode = absent; byte mode = present.
- `n` — input length (felts in felt mode, bytes in byte mode).
- `domain` — user-specified 31-bit domain tag.
