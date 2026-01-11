# IES (Integrated Encryption Scheme)

An Integrated Encryption Scheme (IES) implementation that combines key agreement with authenticated encryption to enable secure public-key encryption. Also known as "sealed boxes."

## Overview

The sealed box construction allows encrypting messages to a recipient using only their public key, without requiring prior key exchange or shared secrets.

## How It Works

1. **Sealing (Encryption)**:
   - Sender generates an ephemeral key pair
   - Derives a shared secret using ECDH between ephemeral private key and recipient's public key
   - Encrypts the message using the shared secret with an AEAD scheme
   - Returns the ciphertext along with the ephemeral public key

2. **Unsealing (Decryption)**:
   - Recipient derives the same shared secret using ECDH between their private key and the ephemeral public key
   - Decrypts and authenticates the message using the shared secret

## Available Schemes

### K256XChaCha20Poly1305

Best for general-purpose applications requiring secp256k1 compatibility:

```rust
use miden_crypto::{
    dsa::ecdsa_k256_keccak::SecretKey,
    ies::{SealingKey, UnsealingKey},
};
use rand::rng;

let mut rng = rng();
let secret_key = SecretKey::with_rng(&mut rng);
let public_key = secret_key.public_key();

let sealing_key = SealingKey::K256XChaCha20Poly1305(public_key);
let unsealing_key = UnsealingKey::K256XChaCha20Poly1305(secret_key);

let sealed = sealing_key.seal_bytes(&mut rng, b"hello").unwrap();
let opened = unsealing_key.unseal_bytes(sealed).unwrap();
```

### X25519XChaCha20Poly1305

Best for general-purpose applications **not** requiring secp256k1 compatibility:

```rust
use miden_crypto::{
    dsa::eddsa_25519_sha512::SecretKey,
    ies::{SealingKey, UnsealingKey},
};

let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);
```

### K256AeadRpo

Best for STARK proof systems requiring secp256k1 compatibility:

```rust
let sealing_key = SealingKey::K256AeadRpo(public_key);
let unsealing_key = UnsealingKey::K256AeadRpo(secret_key);
```

### X25519AeadRpo

Best for STARK proof systems **not** requiring secp256k1 compatibility:

```rust
let sealing_key = SealingKey::X25519AeadRpo(public_key);
let unsealing_key = UnsealingKey::X25519AeadRpo(secret_key);
```

## Data Types

### Bytes

```rust
let sealed = sealing_key.seal_bytes(&mut rng, b"hello world").unwrap();
let opened = unsealing_key.unseal_bytes(sealed).unwrap();
```

### Field Elements

```rust
use miden_crypto::Felt;

let elements = [Felt::new(1), Felt::new(2), Felt::new(3)];
let sealed = sealing_key.seal_elements(&mut rng, &elements).unwrap();
let opened = unsealing_key.unseal_elements(sealed).unwrap();
```

**Important**: Messages sealed as one type must be unsealed using the corresponding method.

## Use Cases

- Public-key encryption
- Encrypting to recipients without prior key exchange
- Secure messaging systems
- Applications requiring sealed box functionality

## Related

- [ECDH](ecdh.md): Underlying key exchange
- [Key Exchange Overview](overview.md)

