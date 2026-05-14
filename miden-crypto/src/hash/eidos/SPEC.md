# Eidos - Design and Specification

## 1. Overview

Eidos is a cryptographic hash function with three conceptual layers:

- **BLAKE3 core** - the shared 7-round BLAKE3 compression core over `u32` words. This layer is mode-agnostic and is deliberately specified so that a future standard-BLAKE3-compression VM operation can reuse it.
- **BlakeG mode** - a Goldilocks-tailored specialization of that core. BlakeG owns the field packing, the 252-bit subspace mask, and the init-time binding of Eidos length/domain information.
- **Eidos** - the public hash API built on BlakeG mode. Eidos owns padding, domain assignment, the meaning of the mode bit, and the Miden-facing API surface.

Goldilocks is the prime field `F_M` with modulus:

```text
M = 2^64 - 2^32 + 1
```

A `Felt` is one canonical element of this field, represented by an integer in
`[0, M)`. A `Word = [Felt; 4]` is Eidos's 4-Felt digest type.

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
- **AEAD runway.** The compression interface should leave room for efficient native-Felt encryption, while keeping the final keystream finalizer and extraction rate as explicit security questions.
- **Modularity.** BLAKE3 core logic, BlakeG field packing, and Eidos framing should stay separable. Padding, domain assignment, and mode-bit semantics belong to Eidos, while packing and masking belong to BlakeG mode.
- **Future standard-BLAKE3 compression support.** BlakeG-specific choices must not be phrased as chiplet-wide facts. A future sibling operation should be able to route standard BLAKE3 `(counter_lo, counter_hi, block_len, flags)` into `v[12..16)` and expose raw `u32` output without changing the shared round function.

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

The current BlakeG operation only exposes the digest half of the BLAKE3 compression output. Section 4.8 describes a compatible wide-output form that may be exposed later without changing the core.

---

## 3. Shared BLAKE3 compression core

### 3.1 Core inputs

The shared core is a BLAKE3 compression-core function over 32-bit words:

```text
core(h: [u32; 8], m: [u32; 16], p: [u32; 4]) -> ([u32; 8], [u32; 8])
```

where:

- `h[0..8)` is the input chaining value.
- `m[0..16)` is the 512-bit message block.
- `p[0..4)` supplies the final four initialization words of the BLAKE3 state.

Throughout this spec, `p` denotes this BLAKE3 parameter-tail input. The
Goldilocks modulus is written as `M`.

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

This separation is intentional. The shared core does not bake in BlakeG's constant choice for `v[12..16)`, and BlakeG mode does not consume the future standard-BLAKE3-compression input slots.

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

When BLAKE3 compression is used to produce a chaining value, it uses `low`, the folded 8-word value, as the next 256-bit chaining value. The `high` half is available for BLAKE3's output functionality.

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

BlakeG intentionally drops standard BLAKE3's per-call `(counter_lo, counter_hi, block_len, flags)` inputs. Eidos binds the stream-wide information that it needs (`domain`, `MODE_BIT`, and `n`) once into the initial chaining value instead. This keeps the steady-state VM loop to one block load and one compression call.

In current Miden MASM, the block load is `adv_pipe`: it pops two words, i.e. 8 Felts, from the advice stack, overwrites the top two stack words used as the rate/block window, writes those two words to memory at the current pointer, and advances the pointer. For BlakeG's cost model, the important part is that one `adv_pipe` supplies exactly one 8-Felt compression block. The current opcode used for the compression-shaped hash step is `hperm`, inherited from the older sponge/permutation interface. In BlakeG terminology, the equivalent operation is `bcompress`:

```text
adv_pipe
bcompress
```

Equivalently, current implementations may still spell the second line as `hperm` while the chiplet is being reused:

```text
adv_pipe
hperm
```

The important property is the cost shape: no per-block stack traffic except loading the next block and invoking the BlakeG compression.

The fixed BLAKE3-tail `p` value and the Eidos initialization play different roles. The value
`p = [IV[4], IV[5], IV[6], IV[7]]` is used on every BlakeG compression call only
to fill the BLAKE3 working-state tail `v[12..16)`. Eidos domain separation and
length binding live in the chaining-value input `h = cv`: Section 4.4 defines
`cv_0`, and each masked folded output becomes the next `cv`. Thus the
domain/mode/length information is injected once at initialization and then
propagates through the compression chain.

### 4.2 Goldilocks packing convention

At the Miden stack boundary, BlakeG represents the chaining value and digest as
a `Word = [Felt; 4]`. Internally, the BLAKE3 core represents the same chaining
value as eight `u32` lanes. At the input boundary, every canonical Goldilocks
Felt is decomposed into two `u32` lanes:

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

Why mask the top bit on output: a fully utilized 64-bit word can exceed the
Goldilocks modulus `M = 2^64 - 2^32 + 1`. Masking the top bit forces every
output Felt into `[0, 2^63)`, which is strictly below `M` and therefore
canonical in Goldilocks. This is an output-finalization rule, not an input
restriction.

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

BlakeG-mode `bcompress` accepts canonical Goldilocks Felts as inputs. The
chaining value and block Felts are decoded into `u32` lanes using the
decomposition in Section 4.2. The returned chaining value is then masked and
packed, so BlakeG outputs live in `[0, 2^63)^4` even though inputs need not.

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

5. Apply the BlakeG 252-bit subspace mask to the folded chaining value:
   cv_new[1] &= 0x7fff_ffff
   cv_new[3] &= 0x7fff_ffff
   cv_new[5] &= 0x7fff_ffff
   cv_new[7] &= 0x7fff_ffff

6. Return cv_new.
```

### 4.4 BlakeG init chaining word

Eidos constructs the initial BlakeG chaining value at the packed-Felt level. This is the load-bearing formulation for the VM, because it is cheap to compute on the MASM stack.

```text
cv_0 (as 4 Felts) = [
    BASE0,
    BASE1,
    BASE2 + (domain + MODE_BIT_VALUE),
    BASE3 + n,
]
```

where:

| Constant | Value | Meaning |
|---|---:|---|
| `BASE0` | `0x3b67_ae85_6a09_e667` | `pack(IV[0], IV[1])` |
| `BASE1` | `0x254f_f53a_3c6e_f372` | `pack(IV[2], IV[3])` |
| `BASE2` | `0x1b05_688c_0000_0000` | `pack(0, IV[5])`; low lane reserved for `domain + MODE_BIT_VALUE` |
| `BASE3` | `0x5be0_cd19_0000_0000` | `pack(0, IV[7])`; low lane reserved for `n` |
| `MODE_BIT` | `1 << 31 = 0x8000_0000` | byte-mode bit; felt mode uses zero |

There is no extra parameter word in BlakeG init. BlakeG follows the BLAKE3 initialization model, with Eidos-specific domain, mode, and length binding carried by the packed chaining value described above.

Equivalently, the unpacked `u32` chaining state at init is:

```text
h[0] = IV[0]
h[1] = IV[1] & 0x7fff_ffff
h[2] = IV[2]
h[3] = IV[3] & 0x7fff_ffff
h[4] = domain + MODE_BIT_VALUE
h[5] = IV[5] & 0x7fff_ffff
h[6] = n
h[7] = IV[7] & 0x7fff_ffff
```

The masked odd lanes are forced by the packed-Felt convention. They are constants or outputs of the BlakeG mask, not extra caller-controlled degrees of freedom.

### 4.5 Why init uses Felt addition

BlakeG injects `domain + MODE_BIT_VALUE` and `n` via Felt addition, not via bitwise XOR.

```text
BASE2 + (domain + MODE_BIT_VALUE)
BASE3 + n
```

This is a VM cost choice:

- Felt addition is a single field operation on the MASM stack.
- Bitwise XOR of packed Felts would require decomposition into `u32` halves, lookup-backed XOR, and recomposition.

The addition is lane-equivalent to setting the low `u32` lane because the low 32 bits of `BASE2` and `BASE3` are zero and the injected values are bounded by `2^32 - 1`:

```text
domain <= 2^31 - 1
MODE_BIT_VALUE in {0, 2^31}
n <= 2^32 - 1
```

Therefore the additions never carry into the high `u32` lanes that hold masked IV words.

The mode-bit lane is also bitwise-equivalent to setting the bit directly:
`domain <= 2^31 - 1` has bit 31 clear, and `MODE_BIT_VALUE` is either zero or exactly bit 31. Thus `domain + MODE_BIT_VALUE` equals `domain | MODE_BIT_VALUE` as a `u32`.

### 4.6 Mode bit, domain, and length

Eidos has two BlakeG modes, distinguished inside BlakeG init:

| Mode | Caller API | Block semantics | `MODE_BIT_VALUE` | `n` semantics |
|---|---|---|---:|---|
| Felt mode | `hash_elements*`, `merge*` | 8 felts per block, each unpacked to two `u32` lanes | `0` | number of input felts |
| Byte mode | `hash` | 64 bytes per block, little-endian `u32` words | `0x8000_0000` | number of input bytes |

The user domain space is 31 bits: `domain < 2^31`. The top bit of the low lane in slot 2 is reserved for `MODE_BIT`.

`MODE_BIT` is BlakeG-mode-internal. It distinguishes Eidos felt-mode inputs from Eidos byte-mode inputs. It is not a chiplet-level selector between BlakeG and any future standard-BLAKE3-compression operation; such selection should happen at the operation/opcode level.

Length `n` must fit in `u32`. For byte mode this limits a single hash call to 4 GiB. For felt mode this limits the input to `2^32 - 1` felts.

### 4.7 Padding and iteration

Both Eidos modes pad the final block with zeros to the full block width:

- Felt mode: pad with `Felt::ZERO` until the final block contains 8 felts.
- Byte mode: pad with `0u8` until the final block contains 64 bytes.

Empty input rule: if the input is empty, the hash performs one zero-block compression with `n = 0`. There is no special zero-output shortcut. Empty input and single-zero input do not collide by padding alone because their `cv_0` values differ in the `n` slot.

The iteration is:

```text
cv = cv_0(domain, mode, n)
for each padded block:
    cv = BlakeG::compress(cv, block)
return pack_to_word(cv)
```

The zero padding is not self-delimiting. The length `n` in `cv_0` is what separates, for example, `[x]` from `[x, 0]` when both lead to related padded block contents.

### 4.8 Optional wide output

The shared BLAKE3 core naturally computes two 8-word halves:

```text
low[i]  = v'[i]     ^ v'[i+8]
high[i] = v'[i+8]   ^ h[i]
```

The digest-only BlakeG operation returns `low`, masked and packed into 4 Felts. A future BlakeG wide-output operation may also expose `high`, with odd lanes masked after the `v'[i+8] ^ h[i]` XOR and then packed with the same BlakeG convention:

```text
bcompress_wide(cv: Felt^4, block: Felt^8) -> (digest: Felt^4, wide: Felt^4)
```

This should be described as BlakeG wide output, not as standard BLAKE3's full seekable XOF. Standard BLAKE3's XOF uses its own output-block counter and flags; BlakeG's wide output only exposes the second half already computed by one compression.

This section records an interface direction, not a security claim. Treating both halves as independent keystream material, using `high` in an AEAD construction, or extracting more than 4 full-field Felts per compression call requires separate cryptographic analysis for the chosen mode and finalizer.

---

## 5. Security claims

### 5.1 Concrete bounds

- **Collision resistance: 2^126 operations**
- **Preimage resistance: 2^252 operations**

### 5.2 Why 126 / 252

Each digest Felt holds `32 + 31 = 63` bits under the BlakeG packing convention. The digest is `Word = [Felt; 4]`:

- Total digest entropy: `4 * 63 = 252` bits.
- Birthday-bound collision security: `floor(252 / 2) = 126` bits.
- Preimage security: 252 bits.

The 2-bit gap relative to BLAKE3's 128-bit collision claim follows from the chosen output finalizer. The digest loses 4 bits of state relative to BLAKE3's 256-bit chaining value, one mask bit per odd lane; the birthday bound halves that loss, giving the 2-bit collision-security gap from 128 to 126. Section 5.5 specifies the finalizer and records the question of alternative finalizers as open research.

### 5.3 Indifferentiability model

Eidos's iteration is a length-injecting prefix-free Merkle-Damgard variant. The total length `n` is bound at init, and padding is deterministic from `n`, so every input length corresponds to a distinct initial chaining value. Inputs of the same length are pairwise non-prefix-comparable unless they are identical, so distinct inputs cannot share an iteration prefix solely because one is a strict prefix of the other.

This is the prefix-free property used by Coron, Dodis, Malinaud, and Puniya, *Merkle-Damgard Revisited: how to Construct a Hash Function* (CRYPTO 2005), when the underlying compression function is modeled as ideal.

The security bound matches the digest's collision security: 126 bits.

Length-extension attacks are blocked in the Eidos hash: extending a digest by `k` blocks would require the hash under `Init(domain, mode, n + k)`, while the observed digest was produced under `Init(domain, mode, n)`. The returned digest is not a valid intermediate chaining value for the longer hash call.

### 5.4 Round count

BlakeG inherits BLAKE3's 7-round core choice.

- BLAKE3 uses 7 rounds with a 128-bit security target, defended in the BLAKE3 specification.
- BlakeG inherits BLAKE3's ARX round function, message schedule, and compression-output wiring as specified above.
- BlakeG's output mask costs 4 bits of state/digest entropy; this is accounted for in the 126/252-bit target.

This vouching applies to compression-mode use. Exposing a bare permutation without the BLAKE3 compression output wiring would require separate analysis.

### 5.5 Output finalizer

BlakeG applies a fixed output finalizer to the raw BLAKE3 compression output: the high-bit mask on odd `u32` lanes, defined in Section 4.2 (packing convention) and Section 4.3 (compression signature). This mask is the normative finalizer for this specification.

Two properties of BlakeG output follow directly from the finalizer choice:

- Each output Felt lives in the subspace

  ```text
  S = [0, 2^63) subset F_M
  ```

  so a digest lives in `S^4`, which is a proper subset of `F_M^4`.

- Digest entropy is `4 * 63 = 252` bits rather than `4 * 64 = 256`, which is what yields the 126-bit collision-security claim of Section 5.2 (versus a BLAKE3-style 128-bit target). It also means BlakeG outputs cannot be used directly as uniform full-field masks for CTR encryption over arbitrary Goldilocks Felts; see Section 7.0.

These are properties of the design choice, not artifacts of an interim implementation. The hash security claims in Section 5.1 are stated against this finalizer. Section 7 explains why native-Felt AEAD may require a different keystream finalizer from the hash finalizer.

Implementation note: any implementation that witnesses Felts as `u32` limbs
must enforce the canonical Felt decomposition from Section 4.2. The
mechanism for doing so is implementation-specific and belongs in the relevant
AIR or circuit specification.

#### Open question: alternative finalizers

Whether a different output finalization could simultaneously close the 2-bit collision-security gap (lifting digest entropy from `252` to `256` and collision security from `126` to `128`) and remove the field-uniformity constraint shaping the AEAD discussion in Section 7 is an open research question.

---

## 6. Design rationale

### 6.1 Why not use standard BLAKE3 per-call parameters in BlakeG mode

Standard BLAKE3 places per-call parameters in `v[12..16)`:

```text
v[12] = counter_lo
v[13] = counter_hi
v[14] = block_len
v[15] = flags
```

BlakeG does not use these per-call parameters. The values Eidos needs to bind
(`domain`, `MODE_BIT`, and `n`) are fixed for the entire hash call, so BlakeG
places them in the initial chaining value `cv_0` instead. Once injected there,
they are carried forward by the chaining state. This keeps each compression
call's stack interface to `(cv, block)` and avoids extra per-block inputs in the
hasher chiplet.

This is a BlakeG-mode choice. The shared BLAKE3 core still exposes the `p` input conceptually, and a future standard-BLAKE3-compression operation can route runtime `(counter_lo, counter_hi, block_len, flags)` into `v[12..16)`.

### 6.2 Why `v[12..16)` is IV constants in BlakeG mode

Since BlakeG mode does not take per-call parameter inputs, it fixes the BLAKE3
parameter tail to the remaining IV words:

```text
v[12..16) = IV[4..8)
```

Together with the standard BLAKE3 placement `v[8..12) = IV[0..4)`, this makes
the full upper half of the working state constant:

```text
v[8..16) = IV[0..8)
```

BlakeG mode does **not** set `v[12..16)` to zero.

### 6.3 Why one MODE_BIT in slot 2 instead of a separate mode slot

Domain space reduction from `2^32` to `2^31` is modest. Adding a separate slot for the mode bit would consume a full init lane or require additional stack manipulation. The current layout keeps init to two Felt additions and four constants.

### 6.4 Compression op signature

The BlakeG-mode chiplet operation takes `(cv, block)` only:

```text
bcompress(cv: Felt^4, block: Felt^8) -> Felt^4
```

This:

- matches BlakeG's mode-specific signature;
- works with Miden VM stack patterns where `mem_stream` / `adv_pipe` supplies the next two words, i.e. 8 Felts, from memory/advice into the compression stack window while the persistent chaining state lives nearby;
- avoids carrying per-block params across the iteration.

This does not imply that the chiplet can only ever support BlakeG mode. Future sibling operations may add stack inputs and selector-gated wiring for other modes.

### 6.5 MASM call pattern

BlakeG mode is designed so that the init prologue pays for Eidos-specific binding once, and the steady-state loop stays minimal:

```text
# Init
push.BASE3 push.n add
push.BASE2 push.(domain + MODE_BIT_VALUE) add
push.BASE1
push.BASE0
padw padw

# Absorb full blocks
repeat.NUM_BLOCKS
    adv_pipe      # load next 8-Felt block into the stack window
    bcompress     # current implementations may spell this hperm
end
```

The exact stack placement is an implementation detail, but the cost shape is normative for BlakeG mode: two Felt additions at init, no per-block parameter pushes, and one compression call per block. This is why `n`, `domain`, and `MODE_BIT` live in `cv_0` rather than in `v[12..16)`.

---

## 7. AEAD direction (future work)

Eidos AEAD is a separate effort, deferred until the hash function ships. This section sketches native-Felt construction families and records the open problem that the CTR side of any final AEAD design must resolve.

Both options share an Encrypt-then-MAC architecture:

- **Encryption**: CTR-like keystream generation using BlakeG as a PRF. The sketches below assume an approved keystream finalizer which produces 4 full-field Felts per `bcompress` call.
- **Authentication**: a tag computed over `(nonce || AD || ciphertext || lengths)` using either the Eidos hash family (Option A) or polynomial evaluation in `F_M^2` (Option B).

The CTR side has an open problem: the normative BlakeG output Felts do not span
the full Goldilocks field (see Section 7.0). The sketches in Sections 7.1-7.3
therefore analyze the construction under an explicit 4-Felt full-field
keystream-finalizer assumption. The MAC side is unaffected by this gap.

This future-work section intentionally remains in the hash spec because it informs decisions that are hard to revisit later, especially the final keystream finalizer and extraction rate.

Neither option exposes BlakeG to a chosen-key setting. Session key derivation
uses a public initialization chaining value but places the secret key in the
message block. The encryption loop then uses the secret-derived `K_ctr` as the
chaining value, and the MAC starts its authenticated input with secret
`K_mac || nonce` before any attacker-controlled data. Thus attacker-controlled
data is handled in the chosen-message regime relevant to the 7-round BLAKE3
compression-core security discussion in Section 5.4.

### 7.0 Open problem: full-entropy keystream

Per the finalizer choice in Section 5.5, BlakeG output Felts live in the subspace

```text
S = [0, 2^63) subset F_M
```

This is not a uniform full-field distribution, so using these Felts directly as CTR masks `c = m + k mod M` over arbitrary plaintext Felts is not IND-CPA secure.

**The break.** If `m = 0`, then `c = k`, so `c in S` with probability 1. If `m = 2^63`, then `c = 2^63 + k mod M`. Since `M = 2^64 - 2^32 + 1`, reduction happens only for the last `2^32 - 1` possible values of `k`, so `c` lies in `[2^63, M)` with probability about `1 - 2^-31` and in `[0, 2^32 - 1)` with probability about `2^-31`. A single ciphertext distinguishes the two plaintexts with overwhelming advantage. This is a full IND-CPA break for native field-element encryption, not a small long-message bias.

This subspace issue affects encryption, not authentication. It matters when
BlakeG output is used as an additive CTR mask, because a mask restricted to `S`
does not hide arbitrary plaintext Felts after addition modulo `M`.

The MAC side does not require full-field additive masks. Option A relies on the
unpredictability and collision resistance of keyed Eidos tags. Option B uses an
evaluation point `r` sampled from the BlakeG output subspace, and its forgery
bound explicitly accounts for that 126-bit support.

**This spec does not resolve the gap.** For the AEAD sketches below, we assume
an approved BlakeG keystream finalizer which, for each keyed `bcompress` call on
a distinct counter block, produces 4 Felts computationally indistinguishable
from uniform over `F_M^4`.

This assumption abstracts over the unresolved finalization problem discussed in
Section 5.5. It may be satisfied by replacing the current mask-and-pack
finalizer, by using the optional wide-output interface internally, or by another
finalization map. Whether BlakeG can safely extract more than 4 full-field
keystream Felts per compression call remains an open problem and is not counted
in the throughput estimates below.

Within Sections 7.1-7.3, define:

```text
KeystreamBlock(cv, block) = KeystreamFinalizer(bcompress(cv, block)) in F_M^4
```

This notation is shorthand for `bcompress` followed by the assumed keystream
finalizer. It is not a claim about the current mask-and-pack digest output.

### 7.1 Common architecture

#### 7.1.1 Session key derivation

A single secret key `K` and a per-encryption nonce `Nonce`, each 4 Felts, seed the session via two domain-separated derivations:

```text
K_ctr = BlakeG::compress(Init(AEAD_CTR_DOMAIN, n=8), [K(4), Nonce(4)])
K_mac = BlakeG::compress(Init(AEAD_MAC_DOMAIN, n=8), [K(4), Nonce(4)])
```

Both are 4-Felt PRF keys, derived once per session and stored read-only inside the encryption and authentication loops. Domain separation between the derivations keeps `K_ctr` and `K_mac` independent under the PRF security of BlakeG.

Option B reinterprets `K_mac` as four Felts holding two `F_M^2` elements `r` and `s` for the Wegman-Carter-Shoup construction; see Section 7.3.

#### 7.1.2 CTR encryption

```text
keystream_lo = KeystreamBlock(K_ctr, [counter=2i,   padding(7)])
keystream_hi = KeystreamBlock(K_ctr, [counter=2i+1, padding(7)])
keystream    = keystream_lo || keystream_hi
ciphertext_i = plaintext_i + keystream
```

Decryption uses subtraction instead of addition. No inverse compression operation is needed.

Here `padding(k)` denotes `k` `Felt::ZERO` values, used to fill the 8-Felt block after the counter. The counter is a `u32` encoded as a canonical Felt via `Felt::from(counter)`, equivalently the low 32-bit lane holds the counter and the high 32-bit lane is zero. Under the 4-Felt keystream assumption, the counter advances by 2 per 8-Felt plaintext block, supporting up to `2^31` plaintext blocks per `(K, Nonce)` pair.

### 7.2 Option A: CTR + Eidos hash MAC

#### 7.2.1 Construction

After CTR encryption, compute the tag by hashing the canonical authenticated input keyed with `K_mac`:

```text
mac_input = K_mac(4) || nonce(4) || AD(...) || ciphertext(...) || ad_len(1) || ct_len(1)
tag       = Eidos::hash_elements_in_domain(mac_input, AEAD_TAG_DOMAIN)
            // 4 Felts (Word)
```

`K_mac` as a prefix turns `Eidos::hash_elements_in_domain` into a keyed hash. `nonce` is included redundantly but may be removed in a final AEAD spec. `ad_len` and `ct_len` are lengths in Felts encoded as Felts, preventing AD/ciphertext boundary-shifting attacks.

Decryption flow:

1. Recompute `tag'` from the received `(nonce, AD, ciphertext)`.
2. Constant-time compare `tag' == tag_received`. If unequal, reject and do not decrypt.
3. If equal, decrypt as in Section 7.1.2.

#### 7.2.2 Security

- **Confidentiality (IND-CPA)** is conditional on resolving the full-entropy keystream problem in Section 7.0. With that resolution in place, confidentiality comes from the PRF security of BlakeG keyed by `K_ctr` in CTR-like mode.
- **Integrity (INT-CTXT)** comes from the unforgeability of length-bound, keyed `Eidos::hash_elements_in_domain`. Because Eidos is prefix-free via length injection, the secret-prefix construction `Hash(K_mac || M)` is analyzed as a keyed hash over the authenticated message. Internal state collision resistance is bounded by the 126-bit birthday security of the 252-bit BlakeG chaining state.
- **Combined IND-CCA** follows by the standard Encrypt-then-MAC composition theorem, assuming the Section 7.0 keystream issue is resolved and the integrity assumptions above hold.

Length-extension attacks on the secret-prefix construction are blocked by the same mechanism as Section 5.3: Eidos binds the total input length `n` at init, so an attacker cannot continue from `Hash(K_mac || M)` to `Hash(K_mac || M || M')`. The longer input uses a distinct initial chaining value and must be recomputed from the secret prefix.

Architectural note on block alignment: in felt mode, one compression block is exactly 8 Felts. Since `mac_input` starts with `K_mac(4) || nonce(4)`, the first block is filled by secret key material and nonce, and attacker-controlled AD/ciphertext starts in the second block. This makes the MAC behave like a secret-IV construction after the first block and avoids mixing attacker-controlled data into the same block as the key prefix.

Forgery probability depends on the final AEAD threat model. Since `K_mac` is derived per nonce, a nonce-unique API gives at most one valid tag per `K_mac`; a blind forgery against an existing nonce guesses a 252-bit tag. Repeated nonce use also repeats `K_ctr` and the CTR keystream, so it is outside the nonce-unique confidentiality model. The final AEAD spec must make the nonce-uniqueness requirement explicit and define any desired misuse-resistant variant separately.

#### 7.2.3 Throughput

Under the 4-Felt keystream assumption, Option A requires three compression calls per 8-Felt plaintext block: two for keystream and roughly one amortized block in the hash MAC.

These counts do not assume that the optional wide-output interface is usable as
AEAD keystream. A different finalizer may change the extraction rate, in which
case the loop-level throughput estimates must be recomputed.

### 7.3 Option B: CTR + algebraic MAC

#### 7.3.1 Construction

Encryption is identical to Section 7.1.2. Authentication uses Wegman-Carter-Shoup polynomial evaluation in `F_M^2` instead of hashing.

`K_mac` is interpreted as four Felts holding two `F_M^2` elements:

```text
K_mac = [r0, r1, s0, s1]
r = (r0, r1) in F_M^2    // polynomial evaluation point
s = (s0, s1) in F_M^2    // Wegman-Carter-Shoup masking term
```

The MAC input is encoded as a sequence of `F_M^2` polynomial coefficients:

```text
mac_input_felts = nonce(4) || AD(...) || ciphertext(...) || ad_len(1) || ct_len(1)
                  // padded with Felt::ZERO to even total length L
T               = L / 2                                         // number of F_M^2 coefficients
m_i             = (mac_input_felts[2i], mac_input_felts[2i+1]) in F_M^2

P(x) = sum_{i=0}^{T-1} m_i * x^{T-1-i}

tag_raw = P(r) + s in F_M^2
tag     = (tag_raw.0, tag_raw.1)
```

Decryption recomputes the tag, performs a constant-time comparison, then decrypts as in Section 7.1.2.

The tag is 2 Felts, about 128 field bits, not a 4-Felt `Word`. For API uniformity the final AEAD API may pad the tag with two zero Felts, but security is carried by the two nonzero Felts.

#### 7.3.2 Security

- **Confidentiality** is the same as Option A: it is conditional on resolving the full-entropy keystream problem in Section 7.0, then follows from PRF security of BlakeG in CTR-like mode keyed by `K_ctr`.
- **Integrity** follows the standard Wegman-Carter-Shoup analysis. The forgery probability per attempt is bounded by approximately `T / 2^126`, where `T` is the number of polynomial coefficients in the MAC input. Under the PRF assumption on BlakeG, `K_mac` is computationally indistinguishable from a uniform 4-tuple over the BlakeG output subspace. The evaluation point `r` then carries `2 * 63 = 126` bits of effective entropy over its support in `F_M x F_M`, which is what enters the Carter-Wegman forgery bound.
- The `+ s` term provides the Wegman-Carter-Shoup masking term for each `(K, Nonce)` pair. Since `s` is also derived from BlakeG output, the final proof should account for its 126-bit subspace support rather than model it as a uniform full-field `F_M^2` mask.

Forgery probability as a function of authenticated payload size, with `L` the total MAC-input length in Felts and `T = L / 2`:

| Authenticated payload | L (Felts) | T (coefficients) | Per-attempt forgery probability |
|---|---:|---:|---:|
| 1 KB | 2^7 | 2^6 | about 2^-120 |
| 1 MB | 2^17 | 2^16 | about 2^-110 |
| 1 GB | 2^27 | 2^26 | about 2^-100 |
| 256 GB | 2^35 | 2^34 | about 2^-92 |

This degradation shape is the same kind of length-dependent polynomial-MAC bound seen in GMAC and Poly1305-style designs. The final AEAD spec must define `MAX_AEAD_AUTHENTICATED_LEN` to enforce the desired security floor.

#### 7.3.3 Throughput

Under the 4-Felt keystream assumption, Option B requires two compression calls per 8-Felt plaintext block for keystream generation, plus one `F_M^2` Horner step per 2 authenticated Felts.

These counts do not assume that the optional wide-output interface is usable as
AEAD keystream. A different finalizer may change the extraction rate, in which
case the loop-level throughput estimates must be recomputed.

---

## 8. Length-binding alternatives

Eidos's resistance to padding collisions and length extension requires binding input length into the iteration. The normative construction is full-length init:

```text
cv_0 = [BASE0, BASE1, BASE2 + (domain + mode), BASE3 + n]
```

An alternative would bind only `n mod RATE` at init and add a separate finalization step. That design is not chosen here because full-length init is simpler and keeps the steady-state loop free of a finalization branch. The alternative remains cryptographically plausible, but it should be treated as a different mode, not as the Eidos mode specified here.

---

## 9. Forward compatibility with standard BLAKE3 compression

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
| initial `h` | Eidos `cv_0` with domain/mode/length injection | caller-provided BLAKE3 chaining value; full hash/chunk/key rules live outside this compression op |
| output | BlakeG odd-lane mask, then two-lane Felt packing | raw BLAKE3 `u32` lanes, no BlakeG mask |
| public operation | `bcompress` style `(cv, block)`; current VM implementations may reuse the `hperm` opcode shape | sibling operation with extra parameter inputs |

Adding such a mode should not require changing the core round function, message schedule, or row count. It would require mode selection, runtime inputs for `v[12..16)`, and different output packing. This spec therefore scopes BlakeG-specific constraints to BlakeG mode and avoids treating the chiplet as BlakeG-only.

This future mode would be a standard BLAKE3 compression operation, not automatically a full standard BLAKE3 hash implementation. The full hash also includes chunking, tree reduction, flags, and output generation rules.

---

## 10. References

### Primary BLAKE3 sources

- O'Connor, J., Aumasson, J.-P., Neves, S., Wilcox-O'Hearn, Z. *BLAKE3: one function, fast everywhere.* BLAKE3 specification. <https://github.com/BLAKE3-team/BLAKE3-specs>
- BLAKE3 team. *BLAKE3 official implementation.* <https://github.com/BLAKE3-team/BLAKE3>

### Cryptanalysis and design literature

- Aumasson, J.-P. *Too Much Crypto.* IACR ePrint 2019/1492.
- Coron, J.-S., Dodis, Y., Malinaud, C., Puniya, P. *Merkle-Damgard Revisited: how to Construct a Hash Function.* CRYPTO 2005.
- Bernstein, D. J. *The Poly1305-AES MAC.* FSE 2005.
- Bellare, M., Namprempre, C. *Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm.* ASIACRYPT 2000.

---

## Appendix A - Notation glossary

- `Felt` - element of the Goldilocks field `F_M`.
- `M` - Goldilocks field modulus, `M = 2^64 - 2^32 + 1`.
- `Word` - `[Felt; 4]`, Eidos's digest type.
- `h` / `cv` - chaining value, `[u32; 8]` inside the BLAKE3 core and `[Felt; 4]` at the BlakeG boundary.
- `m` / `block` - 512-bit message block, `[u32; 16]` inside the BLAKE3 core and `[Felt; 8]` in BlakeG felt mode.
- `p` - the four BLAKE3 state initialization words placed into `v[12..16)`; not the field modulus.
- `v` - 16-word working state inside the compression function.
- `IV[i]` - i-th BLAKE3 IV word.
- `BASE0..BASE3` - packed-Felt BlakeG init constants.
- `MODE_BIT` - `1 << 31`; byte mode uses this bit, felt mode does not.
- `n` - input length, in Felts for felt mode and bytes for byte mode.
- `domain` - user-specified 31-bit domain tag.
- `adv_pipe` - Miden MASM instruction that pops two words, i.e. 8 Felts, from the advice stack, overwrites the top two stack words, writes them to memory at the current pointer, and advances the pointer. In the BlakeG loop, this supplies the next 8-Felt compression block.
- `hperm` - current Miden hash-permutation opcode shape, inherited from the older sponge/permutation interface. It may be the implementation spelling during migration, but it is not the BlakeG primitive name.
- `bcompress` - BlakeG compression operation over `(cv: Felt^4, block: Felt^8) -> Felt^4`.
