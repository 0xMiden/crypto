# Encryption Overview

Miden Crypto provides authenticated encryption with associated data (AEAD) schemes optimized for different use cases.

## Available Schemes

### AEAD-RPO

An authenticated encryption scheme optimized for speed within SNARKs/STARKs. Based on the MonkeySpongeWrap construction using the RPO permutation.

- **Optimized for**: STARK verification
- **Performance**: Highly efficient in zero-knowledge proofs
- **Use case**: When encryption needs to be verified in STARKs

### XChaCha20Poly1305

Extended nonce variant of ChaCha20Poly1305 providing both confidentiality and authenticity.

- **Optimized for**: General-purpose encryption
- **Performance**: ~100x faster than AEAD-RPO for general use
- **Use case**: Standard encryption needs outside of STARK verification

## Choosing a Scheme

### Use AEAD-RPO when:
- You need to verify encryption in STARK proof systems
- Performance in zero-knowledge proofs is critical
- You're building Miden VM applications

### Use XChaCha20Poly1305 when:
- You need general-purpose encryption
- Performance outside of STARKs is important
- You want a widely-adopted standard

## Common Operations

### Encryption

```rust
use miden_crypto::aead::aead_rpo::AeadRpo;
use rand::rng;

let mut rng = rng();
let key = AeadRpo::key_from_bytes(&[0u8; 32]).unwrap();
let plaintext = b"Secret message";
let associated_data = b"metadata";

let ciphertext = AeadRpo::encrypt_bytes(&key, &mut rng, plaintext, associated_data).unwrap();
```

### Decryption

```rust
let decrypted = AeadRpo::decrypt_bytes_with_associated_data(&key, &ciphertext, associated_data).unwrap();
assert_eq!(decrypted, plaintext);
```

## Data Types

Both schemes support:

- **Bytes**: Arbitrary byte data (`encrypt_bytes`/`decrypt_bytes`)
- **Field Elements**: Native field elements (`encrypt_elements`/`decrypt_elements`)

Messages encrypted as one type must be decrypted using the corresponding method.

## Next Steps

- [AEAD-RPO](aead-rpo.md): Learn about STARK-optimized encryption
- [XChaCha20Poly1305](xchacha20poly1305.md): Learn about general-purpose encryption

