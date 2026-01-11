# ECDH (Elliptic Curve Diffie-Hellman)

Elliptic curve Diffie-Hellman key exchange algorithms for secure key agreement. Implementations use ephemeral keys for a "sealed box" approach.

## Available Implementations

### ECDH k256

Using the secp256k1 curve (same as Bitcoin/Ethereum):

```rust
use miden_crypto::ecdh::k256::{EphemeralSecretKey, EphemeralPublicKey, SharedSecret};
use rand::rng;

let mut rng = rng();

// Generate ephemeral key pair
let (ephemeral_sk, ephemeral_pk) = EphemeralSecretKey::random(&mut rng);

// Key exchange
let static_pk = /* recipient's public key */;
let shared_secret = ephemeral_sk.exchange(&static_pk).unwrap();
```

### X25519

Using Curve25519 (modern, high-performance):

```rust
use miden_crypto::ecdh::x25519::{EphemeralSecretKey, EphemeralPublicKey, SharedSecret};
use rand::rng;

let mut rng = rng();

// Generate ephemeral key pair
let (ephemeral_sk, ephemeral_pk) = EphemeralSecretKey::random(&mut rng);

// Key exchange
let static_pk = /* recipient's public key */;
let shared_secret = ephemeral_sk.exchange(&static_pk).unwrap();
```

## Key Material Extraction

Extract key material of arbitrary length from shared secrets:

```rust
let key_material = shared_secret.extract_key_material(32).unwrap(); // 32 bytes
```

## Use Cases

- Secure key agreement
- Building custom encryption protocols
- Key derivation

## Related

- [IES](ies.md): Integrated encryption using ECDH
- [Key Exchange Overview](overview.md)

