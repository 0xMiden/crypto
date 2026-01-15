# RPO Falcon512

A deterministic variant of the [Falcon](https://falcon-sign.info/) signature scheme that uses RPO256 instead of SHAKE256 in the hash-to-point algorithm. This makes the signature more efficient to verify in Miden VM.

## Overview

RPO Falcon512 is a lattice-based signature scheme offering post-quantum security. The key difference from standard Falcon is the use of RPO256 for hash-to-point, making it more efficient for STARK verification.

## Key Properties

- **Type**: Lattice-based (post-quantum)
- **Hash function**: RPO256 (for hash-to-point)
- **Public key size**: 897 bytes
- **Secret key size**: 1281 bytes
- **Signature size**: ~1524 bytes (variable)
- **Security level**: 128 bits (classical), post-quantum secure
- **Signing**: Deterministic

## Usage

### Key Generation

```rust
use miden_crypto::dsa::falcon512_rpo::{SecretKey, PublicKey};
use rand::rng;

let mut rng = rng();
let secret_key = SecretKey::with_rng(&mut rng);
let public_key = secret_key.public_key();
```

### Signing

```rust
use miden_crypto::{dsa::falcon512_rpo::SecretKey, Word, Felt};

let message = Word::new([
    Felt::new(1),
    Felt::new(2),
    Felt::new(3),
    Felt::new(4),
]);

let signature = secret_key.sign(&message);
```

### Verification

```rust
use miden_crypto::dsa::falcon512_rpo::PublicKey;

let is_valid = public_key.verify(&message, &signature);
assert!(is_valid);
```

## Serialization

### Secret Key

```rust
// Serialize
let bytes = secret_key.to_bytes();

// Deserialize
let secret_key = SecretKey::from_bytes(&bytes).unwrap();
```

### Public Key

```rust
// Serialize
let bytes = public_key.to_bytes();

// Deserialize
let public_key = PublicKey::from_bytes(&bytes).unwrap();
```

### Signature

```rust
// Serialize
let bytes = signature.to_bytes();

// Deserialize
let signature = Signature::from_bytes(&bytes).unwrap();
```

## Deterministic Signing

RPO Falcon512 uses deterministic signing. The same message and secret key will always produce the same signature. This is achieved through:

1. **Deterministic hash-to-point**: Uses RPO256 with a fixed nonce
2. **Derandomized sampling**: Uses entropy from the secret key and message

## Differences from Standard Falcon

1. **Hash function**: Uses RPO256 instead of SHAKE256
2. **Deterministic**: Signing is deterministic (standard Falcon uses random nonces)
3. **STARK optimization**: More efficient to verify in STARK proof systems

## Performance

- **Signing**: Moderate (lattice-based operations)
- **Verification**: Fast (especially in STARKs due to RPO256)
- **Key generation**: Moderate

## Security Properties

- **Post-quantum security**: Resistant to quantum computer attacks
- **128-bit classical security**: Strong security against classical computers
- **Deterministic**: No signature malleability issues

## Use Cases

- Post-quantum security requirements
- Applications requiring efficient STARK verification
- Systems where deterministic signatures are preferred
- Long-term security (quantum-resistant)

## Limitations

- **Large keys**: Public keys are 897 bytes, secret keys are 1281 bytes
- **Large signatures**: Signatures are ~1524 bytes (variable)
- **Performance**: Slower than Ed25519 or ECDSA for signing

## Implementation Details

The implementation follows the deterministic Falcon approach described in the [Falcon Deterministic Signatures](https://github.com/algorand/falcon/blob/main/falcon-det.pdf) specification.

Key implementation choices:

- **No platform-specific optimizations**: Uses standard `f64` for portability
- **Deterministic precision**: Avoids non-deterministic floating-point operations
- **Fixed nonce**: Uses versioned fixed nonce for domain separation

## Related

- [ECDSA k256](ecdsa-k256.md): Classical signature scheme
- [Ed25519](ed25519.md): High-performance classical signature scheme
- [Digital Signatures Overview](overview.md)

