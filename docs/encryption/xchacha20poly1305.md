# XChaCha20Poly1305

Extended nonce variant of ChaCha20Poly1305 providing both confidentiality and authenticity. This implementation offers significant performance advantages, showing approximately 100x faster encryption/decryption compared to AEAD-RPO for general-purpose use.

## Overview

XChaCha20Poly1305 is a standard authenticated encryption scheme based on the [XChaCha20Poly1305 specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha). It extends ChaCha20Poly1305 with a longer nonce for better security properties.

## Usage

### Key Generation

```rust
use miden_crypto::aead::xchacha::XChaCha20Poly1305;

let key_bytes = [0u8; 32]; // 32-byte key
let key = XChaCha20Poly1305::key_from_bytes(&key_bytes).unwrap();
```

### Encrypting Bytes

```rust
use miden_crypto::aead::xchacha::XChaCha20Poly1305;
use rand::rng;

let mut rng = rng();
let plaintext = b"Secret message";
let associated_data = b"metadata";

let ciphertext = XChaCha20Poly1305::encrypt_bytes(&key, &mut rng, plaintext, associated_data).unwrap();
```

### Decrypting Bytes

```rust
let decrypted = XChaCha20Poly1305::decrypt_bytes_with_associated_data(&key, &ciphertext, associated_data).unwrap();
assert_eq!(decrypted, plaintext);
```

### Encrypting Field Elements

```rust
use miden_crypto::{aead::xchacha::XChaCha20Poly1305, Felt};

let plaintext = [Felt::new(1), Felt::new(2), Felt::new(3)];
let associated_data = [Felt::new(10), Felt::new(20)];

let ciphertext = XChaCha20Poly1305::encrypt_elements(&key, &mut rng, &plaintext, &associated_data).unwrap();
```

### Decrypting Field Elements

```rust
let decrypted = XChaCha20Poly1305::decrypt_elements_with_associated_data(&key, &ciphertext, &associated_data).unwrap();
assert_eq!(decrypted, plaintext);
```

## Performance

XChaCha20Poly1305 is approximately **100x faster** than AEAD-RPO for general-purpose encryption and decryption. However, it's not optimized for STARK verification.

## Use Cases

- General-purpose encryption
- Applications not requiring STARK verification
- Standard encryption needs
- When performance outside of STARKs is important

## Security Properties

- **Confidentiality**: ChaCha20 stream cipher
- **Authenticity**: Poly1305 MAC
- **Extended nonce**: 192-bit nonce for better security

## Related

- [AEAD-RPO](aead-rpo.md): STARK-optimized alternative
- [Encryption Overview](overview.md)

