# ECDSA k256

Elliptic Curve Digital Signature Algorithm using the `k256` curve (secp256k1) with Keccak256 to hash messages. This is the signature scheme used in Ethereum.

## Overview

ECDSA k256 provides Ethereum-compatible digital signatures. It uses the secp256k1 curve, which is the same curve used by Bitcoin and Ethereum.

## Key Properties

- **Curve**: secp256k1 (k256)
- **Hash function**: Keccak256
- **Secret key size**: 32 bytes
- **Public key size**: 33 bytes (compressed format)
- **Signature size**: 65 bytes (r, s, recovery_id)
- **Security level**: 128 bits

## Usage

### Key Generation

```rust
use miden_crypto::dsa::ecdsa_k256_keccak::{SecretKey, PublicKey};
use rand::rng;

// Generate with OS RNG (requires std feature)
let secret_key = SecretKey::new();

// Or with custom RNG (works in no_std)
let mut rng = rng();
let secret_key = SecretKey::with_rng(&mut rng);

// Get public key
let public_key = secret_key.public_key();
```

### Signing

```rust
use miden_crypto::{dsa::ecdsa_k256_keccak::SecretKey, Word, Felt};

let message = Word::new([
    Felt::new(1),
    Felt::new(2),
    Felt::new(3),
    Felt::new(4),
]);

let signature = secret_key.sign(message);
```

### Pre-hashed Signing

For messages that are already hashed:

```rust
let message_digest = [0u8; 32]; // Keccak256 hash
let signature = secret_key.sign_prehash(message_digest);
```

### Verification

```rust
use miden_crypto::dsa::ecdsa_k256_keccak::PublicKey;

let is_valid = public_key.verify(message, &signature);
assert!(is_valid);
```

### Pre-hashed Verification

```rust
let message_digest = [0u8; 32]; // Keccak256 hash
let is_valid = public_key.verify_prehash(message_digest, &signature);
```

### Public Key Recovery

ECDSA k256 supports public key recovery from signatures:

```rust
use miden_crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature};

let message = Word::new([/* ... */]);
let signature = secret_key.sign(message);

// Recover public key from signature
let recovered_key = PublicKey::recover(message, &signature).unwrap();
assert_eq!(recovered_key, public_key);
```

### Key Commitment

Get a commitment to the public key:

```rust
let commitment = public_key.to_commitment();
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

## Key Exchange

ECDSA secret keys can be used for key exchange:

```rust
use miden_crypto::ecdh::k256::EphemeralPublicKey;

// Get shared secret from ephemeral public key
let shared_secret = secret_key.get_shared_secret(ephemeral_pk);
```

## Use Cases

- Ethereum-compatible applications
- Bitcoin-compatible applications
- Systems requiring secp256k1 compatibility
- Applications needing public key recovery

## Security Considerations

- **Randomness**: Always use a cryptographically secure RNG for key generation
- **Key storage**: Secret keys are automatically zeroized on drop
- **Signature malleability**: Be aware of signature malleability in ECDSA

## Related

- [Ed25519](ed25519.md): Alternative signature scheme
- [RPO Falcon512](falcon512-rpo.md): Post-quantum alternative
- [Digital Signatures Overview](overview.md)

