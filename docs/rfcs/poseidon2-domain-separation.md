# RFC: Poseidon2 Capacity Tags

Status: draft

## Summary

Miden uses Poseidon2 in several protocol-visible places: Merkle trees, SMTs,
MMRs, MAST nodes, STARK commitments, recursive verifier transcripts, and
precompile/PVM integrations. These uses should not rely on informal conventions
or raw helper calls to distinguish one commitment from another.

This RFC defines one convention for Poseidon2 capacity tags:

```text
capacity = [frame, selector, param0, param1]
selector = (domain_id << 8) | version
```

The first lane, `frame`, belongs to the hash construction. Its meaning is narrow:
variable-length streams set it to `input_len mod rate`; fixed-schedule
compression domains in this RFC set it to `0`.

The remaining lanes belong to the protocol. They identify what is being
committed to and carry at most two small domain parameters.

Protocol-visible commitments use this layout directly. Every lane is a field
element whose canonical representative is in `[0, 2^32)`. The Fiat-Shamir
transcript also starts from a normal typed capacity word; it absorbs larger
context, such as the relation digest, as rate input rather than using it as
capacity.

Merkle inner-node compression is the only untyped primitive. It keeps the
all-zero capacity word for compatibility with the VM hasher chiplet. Every other
protocol-visible commitment must avoid the all-zero capacity word.

## Design Model

The convention separates three questions that are easy to confuse:

1. **How full is the final rate block?**
   This is the job of `frame`. For a variable-length felt stream with rate 8,
   `frame = input_len mod 8`. For fixed-schedule compression domains, the input
   shape is fixed by the selector and `frame = 0`.

2. **What does this commitment mean?**
   This is the job of `selector`, `param0`, and `param1`. A selector is a
   registered `(domain_id, version)` pair.

3. **Where is a digest used?**
   A digest may be a leaf, an inner node, a tree root, or a transcript state.
   The role is bound at the layer that owns that meaning. Leaves bind leaf
   meaning; inner nodes bind tree structure; roots are bound where they are
   consumed.

This keeps the common case simple:

```text
capacity = domain_specific_constructor(...)
digest   = poseidon2_hash(payload, capacity)
```

Callers should use named constructors, not hand-assembled capacity words.

## Goals

- Define one capacity layout for protocol-visible Poseidon2 commitments.
- Keep the hash-owned length lane separate from protocol-owned domain tags.
- Make tags cheap to construct in MASM and straightforward to validate at
  decoder/API boundaries.
- Preserve the current `len mod 8` ergonomics for variable-length felt streams.
- Make domain assignments explicit through registered numeric selectors.
- Avoid helper hashes or ad-hoc string hashes for consensus-critical domains.
- Support per-domain versioning.
- Make Rust, MASM, AIR-facing code, and recursive verifiers use the same
  constructors and constants.

## Non-goals

- This RFC does not change the Poseidon2 permutation.
- This RFC does not define a generic byte-hashing API.
- This RFC does not remove low-level raw Poseidon2 helpers used by tests or
  non-consensus internal code.
- This RFC does not finalize every numeric domain assignment.

## Terminology

`Felt`
: A field element in the Miden base field.

`Word`
: Four field elements.

`u32`-encoded field element
: A field element whose canonical representative, interpreted as an integer, is
  in `[0, 2^32)`.

`frame`
: The hash-owned capacity lane. It encodes a small integer. For variable-length
  felt streams, `frame = input_len mod 8`. For fixed-schedule compression domains
  in this RFC, `frame = 0`. Domains do not assign their own meaning to this lane.

`domain_id`
: A registered 24-bit integer identifying one semantic domain.

`version`
: An 8-bit per-domain version.

`selector`
: A 32-bit value encoding `(domain_id, version)`:

```text
selector = (domain_id << 8) | version
```

`DomainTag`
: The protocol-owned part of the capacity word:

```text
[selector, param0, param1]
```

`Capacity`
: The full tag-initialized Poseidon2 capacity word:

```text
[frame, selector, param0, param1]
```

## Normative Rules

### 1. Capacity Layout

Except for the reserved Merkle inner-node primitive in Rule 5, every
protocol-visible Poseidon2 use that initializes capacity MUST use:

```text
[frame, selector, param0, param1]
```

All four lanes MUST be `u32`-encoded field elements.

This bounds the capacity-tag space to 128 bits: four field elements whose
canonical representatives are restricted to `[0, 2^32)`. The security rationale
below relates this choice to the Sponge2 analysis.

The selector MUST encode:

```text
selector = (domain_id << 8) | version
```

with:

- `domain_id < 2^24`;
- `version < 2^8`;
- `domain_id = 0` reserved;
- `version = 0` reserved and not valid for new domains.

Unused parameter lanes MUST be set to zero.

Each selector that tag-initializes a one-shot hash MUST denote one fixed sponge
schedule: absorb that domain's payload under its capacity tag, then squeeze one
digest. A selector MUST NOT be reused for two different absorb/squeeze shapes.

This fixed-schedule rule applies to capacity-domain selectors. Transcript labels
are not registry entries; they are local constants in the transcript grammar and
are absorbed as data rather than used as capacity tags.

### 2. Domain Constructors

Each semantic domain MUST define a constructor that returns the full capacity
word for that domain.

Examples:

```text
mast::basic_block_capacity()
  -> [0, MAST_BASIC_BLOCK_NODE_V1, 0, 0]

mast::join_capacity()
  -> [0, MAST_JOIN_NODE_V1, 0, 0]

smt::bucket_leaf_capacity(num_entries)
  -> [0, SMT_BUCKET_LEAF_V1, num_entries, 0]

mmr::peaks_capacity(num_leaves)
  -> [0, MMR_PEAKS_V1, num_leaves_lo_u32, num_leaves_hi_u32]
```

Call sites SHOULD NOT manually assemble capacity lanes unless they are
implementing one of these constructors.

Constructors MAY accept a full input length and compute `len mod 8`, or they MAY
accept `len_mod_8` directly when that value is already available.

### 3. Variable-Length Felt Streams

For variable-length felt streams absorbed with Poseidon2 rate 8, the constructor
MUST set:

```text
frame = input_len mod 8
```

where `input_len` is the number of field elements before final-block padding.

The selector identifies the semantic domain. There is no generic consensus
domain named `FELT_VAR_HASHING`.

Example for a variable-length PVM payload:

```text
input_len = chunk_payload.len()
capacity  = pvm::chunk_capacity(input_len, params...)
digest    = poseidon2_hash_elements_with_capacity(chunk_payload, capacity)
```

Here `pvm::chunk_capacity` sets `frame = input_len mod 8`. The payload passed to
the hash helper is the unpadded felt stream; the helper pads only the final
partial rate block before applying the permutation.

Some domains define their payload as an already padded canonical encoding. In
that case `input_len` is the encoded length, not the shorter semantic length.
This is how `MMR_PEAKS_V1` keeps `frame = 0`.

### 4. Fixed-Schedule Compression

For fixed-schedule compression domains defined by this RFC, `frame` MUST be
zero. Their absorb shape is fixed by the selector, so there is no variable final
rate block for `frame` to describe.

`param0` and `param1` SHOULD be zero unless the domain gives them an explicit
meaning.

Example:

```text
capacity = mast::join_capacity()   // [0, MAST_JOIN_NODE_V1, 0, 0]
rate     = [left_digest, right_digest]
```

The generic Merkle two-to-one compression is not a typed fixed-schedule domain. It
is the reserved all-zero primitive defined in Rule 5.

### 5. Merkle Trees

A Merkle tree commitment is separated across three layers:

- inner nodes bind tree structure;
- leaf hashes bind leaf meaning;
- root consumption binds tree role.

#### 5.1 Inner nodes

Merkle inner-node compression MUST use all-zero capacity:

```text
MerkleInner(left, right):
  capacity = [0, 0, 0, 0]
  rate     = [left, right]
```

The all-zero capacity word is reserved exclusively for Merkle inner nodes:

- `domain_id = 0` is not registrable;
- no other protocol-visible commitment MAY initialize Poseidon2 with all-zero
  capacity;
- `hash_elements` over a payload that would start from all-zero capacity MUST be
  replaced by a typed constructor before becoming protocol-visible.

This matches the VM hasher chiplet, which constrains Merkle-path input rows to
zero capacity for `MPVERIFY` and `MRUPDATE`.

Merkle inner nodes are not domain-separated by tree, layer, or caller. Adding
such domains would make the Merkle-path capacity a per-call operand. The tree's
role is instead bound where the root is consumed.

#### 5.2 Leaves

A structured leaf whose digest is computed from raw data MUST be typed with a
nonzero selector. Examples include SMT bucket leaves, MMR peak commitments, MAST
basic blocks, and STARK matrix-row leaves.

An opaque `Word` leaf is different: the tree stores a caller-supplied digest
without rehashing it. The tree does not reframe such a leaf. Its meaning must be
bound by the caller, either upstream in the digest itself or downstream where the
root is consumed.

#### 5.3 Roots

An inner node binds tree structure, not application role. The role of the
resulting root MUST be bound where the root is consumed.

Examples:

```text
transcript.absorb(MAIN_TRACE_ROOT, root)
transcript.absorb(FRI_ROUND_ROOT, round_index, folding_pow_nonce, root)
```

The transcript grammar MUST say exactly how each root is absorbed. For example,
`round_index` and `folding_pow_nonce` are single field elements in fixed
positions next to the FRI round root. Variable-length values, if any, must carry
an explicit length.

#### 5.4 Soundness obligations

Leaving Merkle inner nodes untyped is sound only when all of the following hold:

1. Structured leaves are typed.
2. Tree topology is fixed or bound to the commitment.
3. Roots are consumed under a typed role.
4. The all-zero capacity word is used only for Merkle inner nodes.

For ordinary fixed-depth Merkle paths, topology is the path depth checked by the
verifier. For an MMR, topology is the forest shape, so `MMR_PEAKS_V1` binds
`num_leaves`.

### 6. Fiat-Shamir Transcripts

The Fiat-Shamir transcript is not a one-shot hash. It is a long-lived duplex
sponge that absorbs commitments and public values, then squeezes challenges.
This is the one place where the fixed one-shot selector rule is not enough.

Miden transcripts start from their own typed capacity word and absorb a typed
relation digest before any challenge is drawn.

`STARK_TRANSCRIPT_INIT_V1` is a capacity selector for the transcript duplex
grammar defined in this section. It is not a one-shot hash selector.

#### 6.1 Derive the relation digest

The relation digest is an ordinary tag-initialized hash of the encoded AIR
relation:

```text
RELATION_DIGEST = poseidon2(
  capacity = [encoded_relation_felt_count mod 8, STARK_RELATION_DIGEST_V1, 0, 0],
  rate     = encoded_relation,
)
```

For the current recursive verifier, `encoded_relation` is the encoded ACE circuit
stream. That stream is already 8-aligned, so the current frame is `0`.
The encoding MUST be canonical and injective. If the relation encoding changes,
`STARK_RELATION_DIGEST_V1` must be replaced by a new version.

`RELATION_DIGEST` binds the AIR/relation component of the verification
statement. It does not bind the full statement by itself; instance-specific
public inputs are absorbed later.

#### 6.2 Initialize the transcript and absorb the relation digest

The transcript itself starts from a normal capacity tag:

```text
transcript.capacity = [0, STARK_TRANSCRIPT_INIT_V1, 0, 0]
```

The relation digest is absorbed as transcript data, not used as capacity:

```text
transcript.absorb_word(RELATION_DIGEST)
```

In transcript V1 this is one reseed: `rate[0..3] = RELATION_DIGEST`,
`rate[4..7] = 0` from the initialized state, then one permutation.

`STARK_TRANSCRIPT_INIT_V1` versions the transcript grammar: the initial capacity,
relation-digest absorb layout, shape descriptor layout, public-input absorption,
root labels, PCS/LDT message layouts, and challenge schedule. Any semantic
change to that grammar requires a new version.

#### 6.3 Bind shape and statement before challenges

After absorbing `RELATION_DIGEST` and before drawing any challenge, the
transcript MUST absorb:

1. an injective proof-shape descriptor;
2. the instance-specific public inputs.

The shape descriptor must cover every variable part of the transcript schedule:
query count, grinding bits, blowup, final degree, fold arity, PCS/LDT round
counts, and any variable public-input length.

Absorbing this descriptor before the first challenge is equivalent, for this
purpose, to binding the I/O pattern during transcript initialization. What matters
is that the geometry is bound before the first challenge.

#### 6.4 Bind root roles explicitly

Every commitment root absorbed into the transcript MUST carry an explicit role
label. These labels are local to the STARK transcript V1 grammar; they are not
global capacity-domain selectors.

```text
MAIN_TRACE_ROOT = 1
AUX_TRACE_ROOT = 2
QUOTIENT_ROOT = 3
FRI_ROUND_ROOT = 4
```

The wire layout for tagged reseeds is:

```text
non-FRI reseed:
  rate[0..3] = root
  rate[4]    = local role label

FRI-round reseed:
  rate[0..3] = root
  rate[4]    = FRI_ROUND_ROOT
  rate[5]    = round_index
  rate[6]    = folding_pow_nonce
```

If a future transcript uses several PCS/LDT protocols at once, their labels and
layouts must remain distinct inside that transcript grammar, for example
`FRI_ROUND_ROOT`, `STIR_ROUND_COMMITMENT`, and `WHIR_ROUND_COMMITMENT`. Such
labels are still local transcript constants, not global capacity-domain
selectors.

This replaces position-only role binding. Position-only binding is sound for a
fixed transcript script, but explicit labels make the transcript self-describing
and safer to evolve.

#### 6.5 Duplex schedule

The transcript uses an overwrite-and-permute duplex schedule. A reseed writes
its defined rate positions and permutes. Unused rate positions retain their
previous state unless the operation explicitly overwrites them.

Sampling consumes the rate top-down using an `output_len` counter and permutes
again only when the rate is exhausted.

Both the prover-side `MidenDuplexChallenger` and the core-lib recursive verifier
MUST implement the same wire format.

### 7. Byte Domains

Byte-oriented domains MUST be distinct from felt-oriented domains.

If bytes are packed into field elements before absorption, the domain MUST bind
enough metadata to make the byte encoding prefix-free.

The recommended convention is:

```text
frame = encoded_felt_len mod 8
```

and the byte length is bound either in `param0`/`param1` or in a typed rate
header.

Example:

```text
pvm::keccak_bytes_capacity(encoded_len_mod_8, byte_len)
  -> [encoded_len_mod_8, PVM_KECCAK_BYTES_V1, byte_len_lo_u32, byte_len_hi_u32]
```

### 8. Canonical Validation

Any implementation that accepts a raw capacity word from untrusted input MUST
parse it as a capacity tag and reject it unless all checks pass. This includes
proof data, serialized commitments, PVM/precompile arguments, and generic APIs
that let callers provide capacity words directly.

A decoder MUST validate:

- each lane's canonical representative is in `[0, 2^32)`;
- the selector is registered and allowed in the current context;
- the selector version is supported;
- the frame matches the selected domain's rule, such as `0` for a fixed-schedule
  domain or `encoded_len mod 8` for a variable-length stream;
- parameter lanes match the selected domain's schema;
- unused parameter lanes are zero;
- any escape or sentinel value has exactly one canonical encoding.

The all-zero capacity word is not a valid decoded tag; it is reserved for
internal Merkle inner-node compression. If any check fails, or if the decoder
does not understand a selector, version, frame value, or parameter lane, it MUST
reject the capacity word. This rule matters especially for PVM and precompile tag
decoding.

### 9. Registry

Consensus-critical domains MUST use registered numeric identifiers. They SHOULD
NOT derive domain identifiers by hashing strings into the `u32` selector space.

Hash-derived names are useful for logs, tooling, and non-consensus metadata, but
they are a poor capacity-tag format. If a string hash is truncated or reduced to
fit a `u32` selector, uniqueness becomes probabilistic rather than
registry-enforced. If the full hash output is used directly, it no longer fits
the `u32`-encoded capacity-tag rule. In both cases, assignment and versioning are
harder to review. If a domain must bind a human-readable name or a larger context,
it should absorb that value as payload inside a registered typed constructor, not
turn it into a capacity selector.

Human-readable names are for review and generated constants. The numeric
`(domain_id, version)` assignment is normative.

The central registry contains only Poseidon2 capacity domains: entries that
define selector values for `[frame, selector, param0, param1]` capacity tags. It
does not register transcript-local labels. In the machine-readable registry,
`[[ranges]]` allocates `domain_id` ranges to maintainer repositories, and
`[[domains]]` records concrete capacity-domain assignments.

Transcript labels are intentionally not registered here. They are local to the
transcript relation digest and transcript grammar. Their collision risk is local:
labels must be unique within that transcript, but another transcript with a
different transcript domain or grammar may reuse the same small label values
safely.

The machine-readable registry is `docs/registry/poseidon2-domains.toml`.

### 10. Versioning, Upgrades, and Raw APIs

Versioning is per domain. A domain version changes when the capacity tag or
payload semantics change.

A global protocol version MAY determine which domain versions are accepted, but
it SHOULD NOT be included in every Poseidon2 capacity word unless it is part of
that domain's semantic payload.

Hard forks and protocol upgrades interact with this RFC by changing the set of
accepted selectors in a given context. They do not change the capacity layout.
For example, a fork may stop accepting `SMT_BUCKET_LEAF_V1` for newly written
state and require `SMT_BUCKET_LEAF_V2`, while still allowing old `V1` objects to
be read or migrated under an explicit transition rule.

Old untyped hashes may still need to be checked when reading or migrating old
objects. Such support MUST be explicit: the code should call a named legacy
helper, and only in the context where the old hash is still accepted.

New protocol-visible commitments MUST use typed constructors with `version >= 1`.
The registry-level tag constructor enforces this by rejecting `version = 0`.

Low-level raw Poseidon2 APIs may remain available for tests and non-consensus
internal use.

## Security Rationale

Poseidon2 in Miden uses width 12, rate 8, and capacity 4. The security argument
relies on the usual sponge principle: each logical hash instance starts from a
validated capacity tag. Once that tag is fixed, the adversary controls only the
rate input.

When a capacity word comes from external input, as in PVM/precompile decoding, it
is not trusted as raw sponge state. It is decoded as a capacity tag and accepted
only if it matches an allowed registered domain, supported version, valid frame,
and valid parameters. After that check, different domains start from distinct
capacity tags, and the usual sponge security argument applies.

### Sponge2

The layout follows the Sponge2 / generalized sponge analysis of Ashur and Bhati
for Miden-style parameters. The paper states its result in field elements and
powers of the field size. If `c` is the capacity in field elements, Sponge2 can
use `r0` extra first-call elements for domain separation; Corollary 1 sets
`r0 = c / 2` and bounds the advantage by a term proportional to `1 / p^(c/2)`.

For Miden, `c = 4` over a roughly 64-bit field. The first-call
domain-separation space in the Sponge2 bound has size:

```text
p^(c/2) = p^2 ~= 2^128
```

This is a cardinality statement: it describes the size of the first-call
domain-separation input space. The concrete indifferentiability bound also has
small constant losses, so the same corollary gives about 126 bits of security
for these parameters. Thus `2^128` is the size of the tag-space envelope, while
126 bits is the proof's concrete security estimate.

This RFC uses four `u32`-encoded capacity lanes:

```text
4 * 32 bits = 128 bits
```

This gives a raw capacity-tag envelope of the same size as two field elements,
instead of allowing four unrestricted field elements. Valid tags are further
restricted by the registry and by domain-specific validation. In the ordinary
case, the protocol-owned part is `selector`, `param0`, and `param1`, at most
`3 * 32 = 96` bits; `frame` is hash-owned and usually much smaller than a full
`u32` range. The `u32`-encoded form is also cheaper in MASM and easier to
validate when tags are decoded from external input.

This mapping also matches Sponge2's first-call structure. Sponge2 uses a
padding-derived separator `i` together with the extra first-call domain input.
In this RFC:

- `frame` corresponds to `i`: it is the hash-owned final-block-fill separator;
- `selector`, `param0`, and `param1` are the protocol-owned domain input.

The free protocol namespace is therefore at most `3 * 32 = 96` bits for ordinary
capacity tags, below the `p^(c/2)` bound. Counting `frame` as part of the tag
gives the conservative 128-bit capacity-tag-space bound above.

Sponge2 also explains why `frame` is the hash-owned length lane. Sponge2
separates zero-padded variable-length inputs by the final-block fill: the number
of zero elements needed to make the last block rate-aligned. For rate 8 this is
the same information carried by `len mod 8`. This RFC records that information
directly as:

```text
frame = input_len mod 8
```

Thus `frame` is not a protocol parameter. It is the final-block length value
owned by the hash construction. `selector`, `param0`, and `param1` are the
protocol-owned domain tag.

The paper's Miden application section uses the same parameters (`r = 8`, `c = 4`)
and explicitly discusses "2-to-1 hashing with metadata" as a first-call metadata
use case.

See: Tomer Ashur and Amit Singh Bhati, "Generalized Indifferentiable Sponge and
its Application to Polygon Miden VM", IACR ePrint 2024/911, especially Corollary
1 and Section 7.

The `u32`-encoding restriction is also an engineering rule:

1. `u32`-encoded lanes are easy to construct in MASM and easy to represent in
   constants and registries.
2. Externally supplied tags have a finite, canonical space that decoders can
   validate explicitly.
3. The registry remains enumerable and auditable.

### SAFE

SAFE separates sponge uses by binding an I/O pattern and a domain into the sponge
initialization. This RFC uses the same idea in a specialized form.

For ordinary one-shot commitments, each selector names a fixed sponge schedule:
absorb the domain payload, then squeeze one digest. Because the schedule is fixed
per selector, the only hash-owned value that must remain explicit is the final
block fill, `frame = len mod 8`.

The Fiat-Shamir transcript is different. It has many absorbs and many squeezes,
so the one-shot fixed-schedule rule does not apply. SAFE binds the I/O pattern in
the sponge initialization tag; this RFC uses the same binding principle in a
transcript-friendly form: start from a typed transcript-init capacity, then absorb
the relation digest and an injective shape descriptor before any challenge.

### Sakura

Sakura's main lesson for this RFC is that a tree hash must have one
interpretation. A digest should not be valid both as a leaf hash and an inner
node, or as the root of two different tree shapes, unless the verifier has
already fixed which interpretation is allowed.

Sakura achieves this by coding tree structure into the hash input: leaf vs.
inner node, final node vs. intermediate node, child counts, and related
structure. A system can omit some of that per-node coding only when the missing
structure is fixed or bound somewhere else.

This RFC uses that second route for Merkle inner nodes. Inner nodes remain the
reserved all-zero primitive, but the missing structure is bound by the rules in
Section 5.4: structured leaves are typed, topology is fixed or bound, roots are
consumed under typed roles, and no other protocol-visible commitment may use the
all-zero capacity word. For example, an ordinary Merkle path has a fixed depth
checked by the verifier, while an MMR binds its forest shape through
`num_leaves`. If a future tree has variable topology that is not otherwise bound,
it must add the missing structure explicitly rather than reuse the untyped
inner-node primitive alone.

### Oracle Cloning

Using one permutation as many logical hashes is oracle cloning. It is sound only
when the logical uses are separated. The registry and typed capacity constructors
provide that separation, while the exclusive all-zero reservation prevents other
commitments from aliasing Merkle inner-node compression.

## Domain Registry

Suggested initial ranges:

```text
0x000000            reserved
0x000001..0x00ffff  Miden Crypto primitives and data structures
0x010000..0x01ffff  Miden VM domains
0x020000..0x02ffff  Miden protocol domains
0x030000..0x0fffff  unassigned for future Miden core ranges
0x100000..0x10ffff  Miden ecosystem domains
0x110000..0xffffff  unassigned for future maintained ranges
```

Only allocated ranges appear in the machine-readable registry. Unassigned blocks
are intentional spare capacity for future repositories and should not be treated
as experimental space. Local experiments may use branch-local constants or a
maintainer repository's temporary sandbox, but any merged protocol-visible domain
needs an assigned range and a registry entry.

Each allocated range names a maintainer repository in the machine-readable
registry. The central registry allocates top-level ranges and fills the
crypto-maintained entries; delegated repositories maintain their concrete domain
entries inside their assigned ranges.

Each registry entry should specify:

```text
name:
maintainer:
domain_id:
version:
status:
payload_kind: fixed | felt_stream | byte_stream | custom
frame:
param0:
param1:
rate:
```

Constants with a `_V1` suffix denote full selector values, not raw `domain_id`
values.

### Selector Naming

Selector names should name the protocol object being committed to, not the helper
function that computes it. Prefer:

```text
<AREA>_<OBJECT>_<ROLE>_V<version>
```

where `<ROLE>` is a concrete word such as `LEAF`, `NODE`, `ROOT`, `DIGEST`, or
`TRANSCRIPT_INIT` when that improves clarity. Avoid crate-local acronyms unless
they are already protocol terminology, and avoid names that only describe an
implementation detail.

Examples:

```text
SMT_BUCKET_LEAF_V1
MMR_PEAKS_V1
MAST_JOIN_NODE_V1
STARK_MATRIX_LEAF_V1
STARK_RELATION_DIGEST_V1
STARK_TRANSCRIPT_INIT_V1
```

Transcript labels are not capacity selectors. They are local to a transcript
grammar and do not need the `_V1` suffix.

## Candidate Initial Domains

These are candidate entries, not final assignments.

### Miden Crypto

```text
SMT_BUCKET_LEAF_V1
  payload_kind: felt_stream
  frame = flattened_key_value_element_count mod 8
          (= 0; each entry is 8 felts)
  param0 = num_entries (1..=1024)
  param1 = 0
  rate = flattened sorted (key, value) pairs

MMR_PEAKS_V1
  payload_kind: felt_stream
  frame = padded_peak_element_count mod 8 (= 0)
  param0 = num_leaves low 32 bits
  param1 = num_leaves high 32 bits
  rate = canonical zero-padded peak vector
```

An SMT leaf is a sorted bucket of `1..=1024` `(key, value)` pairs at one
depth-64 position. A single-entry leaf is the same semantic bucket domain with
`num_entries = 1`; a prefix collision changes the bucket contents and
`num_entries`, not the selector. If deletions later leave one entry, the leaf
returns to the `num_entries = 1` form under the same selector.

An empty SMT leaf remains `EMPTY_WORD` under the existing empty-subtree-root
convention.

`MMR_PEAKS_V1` binds `num_leaves` because `num_leaves` is the MMR topology
descriptor. The semantic payload is the canonical zero-padded peak vector, so
the encoded input length is a multiple of 8 and `frame = 0`.

### Delegated VM Domains

The `https://github.com/0xMiden/miden-vm` range is delegated to the VM
repository. Concrete entries in that range should live in the VM repository and
follow this RFC. The examples below are illustrative VM-maintained domains, not
subdivisions of the central registry.

Expected MAST entries include:

```text
MAST_BASIC_BLOCK_NODE_V1
MAST_JOIN_NODE_V1
MAST_SPLIT_NODE_V1
MAST_LOOP_NODE_V1
MAST_CALL_NODE_V1
MAST_SYSCALL_NODE_V1
MAST_DYN_NODE_V1
MAST_DYNCALL_NODE_V1
```

MAST basic blocks need the most care. Their payload is the encoded operation
batches; each batch contributes 8 felts, so the encoded length is
`8 * num_op_batches` and `frame = 0`.

Without a MAST selector, a one-batch basic block is hashed from 8 felts with
all-zero capacity, which has the same shape as a Merkle inner-node merge of two
`Word`s. `MAST_BASIC_BLOCK_NODE_V1` fixes this by giving basic blocks their own
nonzero selector.

Control nodes already use a dedicated control-node hash path, so their migration
is mostly assigning registered selector values. Basic blocks use the linear
basic-block hash path, so they require the real implementation update: use the
typed capacity there and update the matching VM constraints.

`External` MAST nodes do not define a new hash constructor. Their digest is the
digest of the referenced procedure or subtree.

### STARK and Recursive Verifier

Expected recursive-verifier/STARK entries include:

```text
STARK_MATRIX_LEAF_V1
STARK_RELATION_DIGEST_V1
STARK_TRANSCRIPT_INIT_V1
```

The STARK transcript V1 grammar defines these local labels:

```text
MAIN_TRACE_ROOT = 1
AUX_TRACE_ROOT = 2
QUOTIENT_ROOT = 3
FRI_ROUND_ROOT = 4

absorb_root(label, root):
  rate[0..3] = root
  rate[4]    = label

absorb_fri_round_root(round_index, folding_pow_nonce, root):
  rate[0..3] = root
  rate[4]    = FRI_ROUND_ROOT
  rate[5]    = round_index
  rate[6]    = folding_pow_nonce
```

Merkle trees used by STARK commitments and FRI use the untyped inner-node
primitive. Their structured matrix-row leaves are typed with
`STARK_MATRIX_LEAF_V1`, and their roots are role-labeled where they are absorbed
into the transcript.

`STARK_RELATION_DIGEST_V1` is a typed hash of the canonical encoded relation.
`STARK_TRANSCRIPT_INIT_V1` initializes the transcript capacity and versions the
transcript grammar. The relation digest is absorbed as transcript input; it is
not used as capacity.

This changes the existing preload-style initialization:

```text
old: capacity = RELATION_DIGEST
new: capacity = [0, STARK_TRANSCRIPT_INIT_V1, 0, 0]
     absorb_word(RELATION_DIGEST)
```

The same update makes role labels part of the transcript wire format.

### PVM and Precompiles

PVM domains should not pass arbitrary unconstrained capacity words. Each
precompile commitment domain should define its selector and parameter semantics.

Examples:

```text
PVM_EXPR_NODE_V1
  payload_kind: fixed
  frame = 0
  param0 = precompile_kind_or_node_kind, if assigned to this domain
  param1 = domain-specific

PVM_CHUNK_NODE_V1
  payload_kind: felt_stream
  frame = chunk_payload_len mod 8
  param0 = domain-specific
  param1 = domain-specific

PVM_KECCAK_BYTES_V1
  payload_kind: byte_stream
  frame = encoded_felt_len mod 8
  param0 = byte_len low 32 bits
  param1 = byte_len high 32 bits
```

PVM domains define the meaning of their parameter lanes. For byte-stream domains,
`frame` describes the encoded felt stream, while the original byte length must be
bound separately, as in `PVM_KECCAK_BYTES_V1`.

If a domain specifies a parameter lane as `0`, then an externally decoded tag
MUST have `0` in that lane. Any nonzero value is invalid.

## Issue Resolution Matrix

This non-normative section summarizes how the convention resolves the padding
and domain-separation issues that motivated the RFC. The normative rules above
govern if this summary ever drifts.

### Raw Felt Hashing

There is no consensus domain for "plain felt hashing." Every protocol-visible
commitment that hashes felts gets a semantic selector and constructor. Merkle
inner-node compression is the reserved exception (below).

For variable-length felt streams:

```text
frame = input_len mod 8
selector = the semantic domain
```

This preserves the cheap `len mod rate` rule while avoiding a generic
`hash_elements` domain shared by unrelated commitments.

### Merkle Inner Nodes

Merkle inner nodes keep the all-zero capacity primitive:

```text
capacity = [0, 0, 0, 0]
rate     = [left_digest, right_digest]
```

This is the only protocol-visible hash that is intentionally left without a
selector. The all-zero capacity word is reserved exclusively for inner-node
compression. The framework does not introduce per-tree or per-layer Merkle
domains. Instead, leaves are typed, topology is fixed or bound, and roots are
role-bound where they are consumed.

### MMR Peaks

The MMR issue is resolved by binding the forest shape in the domain params:

```text
capacity = [frame, MMR_PEAKS_V1, num_leaves_lo_u32, num_leaves_hi_u32]
```

With the current canonical peak encoding, the payload is padded to a 16-peak
floor and, above that floor, to an even number of peaks. Since each peak is four
felts, the encoded payload is always a multiple of 8 felts, so:

```text
frame = 0
```

If MMR peaks were ever hashed without that canonical padding, the same rule would
still apply:

```text
frame = raw_peak_felt_len mod 8
      = (4 * num_peaks) mod 8
```

`num_leaves` remains a semantic topology parameter, not final-block length
metadata.

### SMT Leaves

The SMT single-entry and multi-entry leaf cases use one semantic domain:

```text
capacity = [0, SMT_BUCKET_LEAF_V1, num_entries, 0]
```

The leaf is a sorted bucket at one depth-64 position. A prefix collision changes
the bucket contents and `num_entries`; it does not create a new selector or a new
subtree domain. If deletions leave one entry, the same selector is used with
`num_entries = 1`. Empty leaves remain `EMPTY_WORD` under the existing
empty-subtree convention.

### MAST

MAST basic blocks and control nodes are typed separately.

Basic blocks get `MAST_BASIC_BLOCK_NODE_V1` because the legacy raw `hash_elements`
form can start from all-zero capacity. A single operation batch is exactly eight
felts, so it has the same shape as a Merkle inner-node merge unless it is typed.

Control nodes use their own selectors (`MAST_JOIN_NODE_V1`,
`MAST_SPLIT_NODE_V1`, and so on). The VM already carries an opcode/domain in the
control-node hashing path, so this is mostly a selector-value migration. Basic
blocks need a real update to the linear basic-block hash path.

### STARK Commitments and FRI

Merkle trees used by STARK commitments and FRI keep the untyped inner-node
primitive. Their leaves use a single structured-leaf domain:

```text
STARK_MATRIX_LEAF_V1
```

The role of each resulting root is bound in the transcript:

```text
MAIN_TRACE_ROOT
AUX_TRACE_ROOT
QUOTIENT_ROOT
FRI_ROUND_ROOT(round_index, folding_pow_nonce)
```

This avoids per-layer inner-node domains for PCS/LDT Merkle trees while still
binding each layer root to its local transcript role.

### Fiat-Shamir Transcript

The transcript is the only long-lived duplex sponge. It still starts from a
normal typed capacity:

```text
RELATION_DIGEST = poseidon2(
  capacity = [encoded_relation_felt_count mod 8, STARK_RELATION_DIGEST_V1, 0, 0],
  rate     = encoded_relation,
)

transcript.capacity = [0, STARK_TRANSCRIPT_INIT_V1, 0, 0]
transcript.absorb_word(RELATION_DIGEST)
```

The relation digest binds the fixed AIR/relation component of the statement. It
does not bind the full statement by itself; the transcript then absorbs the proof
shape, public inputs, and labeled roots before drawing challenges.
`STARK_TRANSCRIPT_INIT_V1` versions this transcript grammar.

### Byte Commitments

For byte payloads, `frame` describes the felt stream actually absorbed by
Poseidon2:

```text
frame = encoded_felt_len mod 8
```

The original byte length must still be bound, either in `param0`/`param1` or in a
typed rate header. `frame` alone is not a byte-length commitment.

### PVM and Precompile Tags

PVM/precompile commitments should not pass arbitrary four-felt values as
capacity. Each commitment family gets a registered selector and validates all
parameter lanes.

If a precompile needs more context than two `u32` params, that context belongs in
a typed rate header or in a separate registered typed commitment, not in
unconstrained capacity lanes.

## API Sketches

These sketches show the intended shape of the API, not final names.

### Rust

```rust
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DomainTag {
    selector: u32,
    param0: u32,
    param1: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Capacity([Felt; 4]);

impl DomainTag {
    /// Structural helper for registered capacity domains.
    ///
    /// This checks only the registry shape. Domain-specific constructors
    /// still validate whether param0/param1 are meaningful for the domain.
    pub const fn new_registered(
        domain_id: u32,
        version: u8,
        param0: u32,
        param1: u32,
    ) -> Self {
        assert!(domain_id != 0 && domain_id < (1 << 24));
        assert!(version != 0);
        Self {
            selector: (domain_id << 8) | version as u32,
            param0,
            param1,
        }
    }
}

impl Capacity {
    /// Structural helper for constructor implementations.
    pub const fn new(frame: u32, tag: DomainTag) -> Self;

    pub const fn fixed(tag: DomainTag) -> Self {
        Self::new(0, tag)
    }

    pub const fn felt_stream(tag: DomainTag, len: usize) -> Self {
        Self::new((len % 8) as u32, tag)
    }

    pub const fn as_word(self) -> Word;
}

pub fn hash_elements_with_capacity<E>(elements: &[E], capacity: Capacity) -> Word
where
    E: BasedVectorSpace<Felt>;

pub fn merge_with_capacity(values: &[Word; 2], capacity: Capacity) -> Word;
```

Domain constructors should live next to the code that maintains the domain. For
example, `smt::bucket_leaf_capacity(num_entries)` validates the bucket size,
while `mmr::peaks_capacity(num_leaves)` validates and encodes the MMR topology
parameter.

Merkle inner-node compression is separate from this typed `Capacity` API. It
keeps the reserved all-zero capacity primitive described in Rule 5.

### MASM

Low-level helpers:

```text
poseidon2::init_with_capacity
poseidon2::hash_elements_with_capacity
poseidon2::merge_with_capacity
```

Typed wrappers:

```text
mast::basic_block_capacity
mast::join_capacity
smt::bucket_leaf_capacity
mmr::peaks_capacity
pvm::<precompile>_capacity
```

Preferred call pattern:

```text
exec.mmr::peaks_capacity
exec.poseidon2::hash_elements_with_capacity
```

not:

```text
push.[frame, selector, param0, param1]   # hand-assembled capacity word
exec.poseidon2::...
```

Raw lane assembly should be limited to the constructor itself.

## Extension Parameters

Some future domains may need more parameter space than two `u32` lanes.

This RFC reserves the following optional convention:

- a domain may designate `u32::MAX` in one parameter lane as an escape value;
- when the escape is used, the extended value MUST be encoded in a typed rate
  header;
- if the value fits inline, the inline form MUST be used;
- domains that do not define an escape MUST reject `u32::MAX` when it would be
  ambiguous.

This preserves upgrade room without allowing multiple encodings of the same
commitment.
