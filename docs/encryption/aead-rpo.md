# AEAD-RPO

Authenticated encryption with associated data (AEAD) scheme optimized for speed within SNARKs/STARKs. Based on the [MonkeySpongeWrap construction](https://eprint.iacr.org/2023/1668) using the RPO permutation.

## Overview

AEAD-RPO is designed to be highly efficient when executed within zero-knowledge proof systems, particularly STARKs. It uses the RPO permutation, making it arithmetization-friendly.

## Usage

### Key Generation

```rust
use miden_crypto::aead::aead_rpo::AeadRpo;

let key_bytes = [0u8; 32]; // 32-byte key
let key = AeadRpo::key_from_bytes(&key_bytes).unwrap();
```

### Encrypting Bytes

```rust
use miden_crypto::aead::aead_rpo::AeadRpo;
use rand::rng;

let mut rng = rng();
let plaintext = b"Secret message";
let associated_data = b"metadata";

let ciphertext = AeadRpo::encrypt_bytes(&key, &mut rng, plaintext, associated_data).unwrap();
```

### Decrypting Bytes

```rust
let decrypted = AeadRpo::decrypt_bytes_with_associated_data(&key, &ciphertext, associated_data).unwrap();
assert_eq!(decrypted, plaintext);
```

### Encrypting Field Elements

```rust
use miden_crypto::{aead::aead_rpo::AeadRpo, Felt};

let plaintext = [Felt::new(1), Felt::new(2), Felt::new(3)];
let associated_data = [Felt::new(10), Felt::new(20)];

let ciphertext = AeadRpo::encrypt_elements(&key, &mut rng, &plaintext, &associated_data).unwrap();
```

### Decrypting Field Elements

```rust
let decrypted = AeadRpo::decrypt_elements_with_associated_data(&key, &ciphertext, &associated_data).unwrap();
assert_eq!(decrypted, plaintext);
```

## Performance

AEAD-RPO is optimized for STARK verification. While it's slower than XChaCha20Poly1305 for general-purpose use, it's significantly more efficient when verification needs to happen within a STARK proof.

## Use Cases

- Encryption that needs to be verified in STARKs
- Miden VM applications requiring encrypted data
- Zero-knowledge proof systems

## Related

- [XChaCha20Poly1305](xchacha20poly1305.md): General-purpose alternative
- [Encryption Overview](overview.md)

