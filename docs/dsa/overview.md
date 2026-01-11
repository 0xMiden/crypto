# Digital Signatures Overview

Miden Crypto provides a set of digital signature schemes supported by default in the Miden VM. These schemes offer different trade-offs in terms of performance, security, and compatibility.

## Available Signature Schemes

### ECDSA k256

Elliptic Curve Digital Signature Algorithm using the `k256` curve (also known as `secp256k1`) with `Keccak` to hash messages.

- **Curve**: secp256k1
- **Hash function**: Keccak256
- **Key size**: 32 bytes (secret), 33 bytes (public, compressed)
- **Signature size**: 65 bytes
- **Use case**: Ethereum compatibility, widely adopted

### Ed25519

Elliptic Curve Digital Signature Algorithm using the `Curve25519` elliptic curve with `SHA-512` to hash messages.

- **Curve**: Curve25519
- **Hash function**: SHA-512
- **Key size**: 32 bytes (secret), 32 bytes (public)
- **Signature size**: 64 bytes
- **Use case**: Modern applications, high performance, strong security

### RPO Falcon512

A variant of the [Falcon](https://falcon-sign.info/) signature scheme using RPO256 instead of SHAKE256 in the hash-to-point algorithm.

- **Type**: Lattice-based signature
- **Hash function**: RPO256 (for hash-to-point)
- **Key size**: 897 bytes (public), 1281 bytes (secret)
- **Signature size**: ~1524 bytes
- **Use case**: Post-quantum security, efficient STARK verification
- **Special feature**: Deterministic signing

## Choosing a Signature Scheme

### Use ECDSA k256 when:
- You need Ethereum compatibility
- You're working with Ethereum-based systems
- You need broad ecosystem support

### Use Ed25519 when:
- You want the best performance
- You need strong security guarantees
- You're building modern applications
- You don't need Ethereum compatibility

### Use RPO Falcon512 when:
- You need post-quantum security
- You want efficient verification in STARKs
- You need deterministic signatures
- Signature size is not a primary concern

## Common Operations

All signature schemes support similar operations:

### Key Generation

```rust
use miden_crypto::dsa::eddsa_25519_sha512::SecretKey;
use rand::rng;

let mut rng = rng();
let secret_key = SecretKey::with_rng(&mut rng);
let public_key = secret_key.public_key();
```

### Signing

```rust
let message = Word::new([/* ... */]);
let signature = secret_key.sign(message);
```

### Verification

```rust
let is_valid = public_key.verify(message, &signature);
```

## No-Std Support

All signature schemes support both `std` and `no_std` contexts. In `no_std` contexts, you must provide your own random number generator for key generation and signing.

## Security Properties

- **ECDSA k256**: 128-bit security level, widely vetted
- **Ed25519**: 128-bit security level, state-of-the-art
- **RPO Falcon512**: Post-quantum security, 128-bit classical security

## Next Steps

- [ECDSA k256](ecdsa-k256.md): Learn about Ethereum-compatible signatures
- [Ed25519](ed25519.md): Learn about high-performance signatures
- [RPO Falcon512](falcon512-rpo.md): Learn about post-quantum signatures

