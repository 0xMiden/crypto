# RFC: BlakeG/Eidos Domain Tags

**Status.** Draft.

This RFC defines one domain-separation convention for protocol-visible uses of the Eidos hash and of constructions built on the BlakeG compression. It specifies only how domain and length information is bound into a hash instance. The construction itself, the BLAKE3 core, BlakeG mode, packing, the mask, and the iteration, is in `SPEC.md`, and concrete domain assignments live in the registry.

## Summary

Eidos binds domain and length information into the **initial chaining value** `cv_0`, once at init, using a four-lane tag.

```text
tag      = [frame, selector, param0, param1]
selector = (domain_id << 8) | version
```

`frame` belongs to the hash construction and carries the input length. `selector`, `param0`, and `param1` belong to the protocol and identify what is being committed to.

## Design model

The convention separates three questions that are easy to confuse.

1. **How long is the input?** This is the job of `frame`. For a variable-length felt or byte stream it is the exact encoded length. For a fixed-schedule domain it is `0`, since the shape is fixed by the selector.
2. **What does this commitment mean?** This is the job of `selector`, `param0`, and `param1`. A selector is a registered `(domain_id, version)` pair.
3. **Where is a digest used?** A digest may be a leaf, an inner node, a root, or a transcript state. That role is bound at the layer that owns it, not in the tag.

## Goals and non-goals

The goals are one tag layout for protocol-visible Eidos commitments, a hash-owned length lane kept separate from protocol-owned domain tags, cheap construction in MASM, explicit registered selectors, and per-domain versioning.

This RFC does not change the BlakeG compression, does not define a generic byte-hashing API, and does not finalize every numeric domain assignment. Those are registry and SPEC concerns.

## Terminology

`Felt` is one canonical element of the Goldilocks field `F_M`, `M = 2^64 - 2^32 + 1`. `Word` is `[Felt; 4]`, the Eidos digest type. `cv_0` is the initial chaining value of a hash instance. `frame` is the hash-owned length lane. `domain_id` is a registered 24-bit integer, `version` an 8-bit per-domain version, and `selector` their packed encoding (Summary).

## Normative rules

### 1. Tag layout and init injection

Every protocol-visible Eidos instance that initializes a chaining value MUST derive `cv_0` from a registered tag, at the unpacked `u32` level, as

```text
cv0_u32 = [
    frame,    IV[1] & 0x7fff_ffff,
    selector, IV[3] & 0x7fff_ffff,
    param0,   IV[5] & 0x7fff_ffff,
    param1,   IV[7] & 0x7fff_ffff,
]
```

or equivalently at the packed-Felt boundary, with `pack(lo, hi) = lo + hi * 2^32`,

```text
cv_0 = [
    pack(frame,    IV[1] & 0x7fff_ffff),
    pack(selector, IV[3] & 0x7fff_ffff),
    pack(param0,   IV[5] & 0x7fff_ffff),
    pack(param1,   IV[7] & 0x7fff_ffff),
]
```

Each of the four tag lanes is a `u32` carried in the **low half** of a packed felt. The four high halves are fixed BLAKE3 IV words with the top bit cleared, which keeps every `cv_0` inside the 252-bit packed-Felt subspace and canonical in `F_M`. The selector's `domain_id` MUST be `< 2^24` and `version` `< 2^8`, with `domain_id = 0` and `version = 0` reserved, so every registered domain uses `domain_id >= 1` and `version >= 1`. Unused parameter lanes MUST be zero.

This is deliberately **not** an arbitrary-IV interface. Only the four low lanes vary. A design that lets a caller provide a raw eight-`u32` chaining value is a different mode and needs separate analysis.

### 2. Domain constructors

Each semantic domain MUST define a constructor that returns the full tag for that domain, and call sites SHOULD use the named constructor rather than assembling lanes by hand. A constructor MAY accept a full input length and compute the encoded length for `frame`.

### 3. Variable-length felt and byte streams

For a variable-length stream the constructor MUST set `frame` to the exact encoded input length, a felt count for felt-stream domains and a byte count for byte-stream domains. Byte-oriented domains MUST be distinct from felt-oriented domains, and the encoding MUST be canonical and injective.

### 4. Fixed-schedule compression

For a fixed-schedule domain, whose input shape is fixed by the selector, `frame` MUST be `0`, since there is no variable length to describe. This is the rule that fixes the AEAD's fixed-schedule domains to `frame = 0`: the key derivations under `AEAD_CTR_DOMAIN` and `AEAD_MAC_DOMAIN`, each over a fixed `[key, nonce]`, and the keystream under `AEAD_KEYSTREAM_DOMAIN`, over `[K_ctr, counter]`.

### 5. Merkle inner nodes

A Merkle inner-node compression MUST use the all-zero tag `[0, 0, 0, 0]`. In Eidos this zeroes only the four tag lanes before they combine with the fixed IV halves, so the chaining value itself is not all zero. The all-zero tag is reserved exclusively for this primitive, since `domain_id = 0` is not registrable, and no other protocol-visible commitment may use it. Leaving inner nodes untyped is sound only when structured leaves are typed, tree topology is fixed or bound to the commitment, and roots are consumed under a typed role. Non-Merkle binary nodes MUST use a registered nonzero selector.

### 6. Fiat-Shamir transcripts

A Fiat-Shamir transcript is not a single hash but a running transcript state, updated by hashing each new value into it and read by hashing the state, with a counter, to draw a challenge. It MUST start from a typed transcript-init tag, hash an injective proof-shape descriptor and the public inputs into the state before any challenge is drawn, and carry an explicit role label on every commitment root it takes in. Transcript labels are local to the transcript grammar and are not registry selectors. The concrete transcript grammar is versioned by its transcript-init selector.

### 7. Canonical validation

Any implementation that accepts a tag from untrusted input MUST decode it and reject it unless every lane is a canonical `u32`, the selector is registered and allowed in context, the version is supported, `frame` matches the selected domain's rule, and the parameter lanes match the domain schema with unused lanes zero. The all-zero tag is not a valid decoded tag, since it is reserved for Merkle inner nodes.

### 8. Registry and versioning

Consensus-critical domains MUST use registered numeric identifiers from the registry rather than hashed strings. Versioning is per domain, and a domain version changes when its tag or payload semantics change. New protocol-visible commitments MUST use a typed constructor with `version >= 1`.

### 9. Keyed use and AEAD

Keyed constructions built on BlakeG MUST place the secret in the **block input** and never in the tag or the chaining value. There is no keyed-IV mode. A session key is derived once under a fixed-schedule domain, as in Rule 4, and a keystream is then produced by a prefix-key form, namely the derived key is prepended to the counter in the block input under a public tag-init chaining value. This keeps one tag-init interface and avoids exposing a caller-chosen chaining value. The full analysis of the keyed modes lives in `SPEC.md`.

## Security rationale

Eidos binds the tag by mapping it injectively into a structured initial chaining value, so two separate claims hold. First, packing is injective on lane-valid tags, which is structural and needs no assumption. Second, deployed initial states are distinct when the registry keeps each registered `(selector, param0, param1)` unique, which is the registry discipline of Rule 8. Given both, distinct valid registered tags give distinct initial states, and the tag can be read back off the state by projection.

Domain separation between hash instances then reduces to the security of BlakeG in this structured-init mode, together with the length-injecting prefix-free Merkle-Damgard argument of `SPEC.md`, which follows Coron, Dodis, Malinaud, and Puniya (CRYPTO 2005) under an ideal compression. Exact length binding in `frame` is what prevents padding and length-extension ambiguity.

The four `u32` lanes give a 128-bit tag space. Restricting lanes to `u32` keeps externally supplied tags finite and easy to validate, and keeps the registry enumerable. Tree-structure and I/O-pattern soundness ride on Rules 5 and 6, and using one compression function for many logical hashes is sound because the registry and typed constructors separate the uses.

## Registry and constructors

The machine-readable registry allocates `domain_id` ranges to maintainer repositories and records concrete domain assignments, which are not duplicated here. Domain constructors and a `DomainTag` / `cv_0` API should live next to the code that maintains each domain.

