# Key Exchange Overview

Miden Crypto provides elliptic curve Diffie-Hellman (ECDH) key exchange algorithms and an Integrated Encryption Scheme (IES) that combines key agreement with authenticated encryption.

## Available Schemes

### ECDH

Elliptic curve Diffie-Hellman key exchange for secure key agreement:

- **ECDH k256**: Using secp256k1 curve
- **X25519**: Using Curve25519

### IES (Integrated Encryption Scheme)

Sealed box implementation combining ECDH with AEAD encryption:

- **K256XChaCha20Poly1305**: secp256k1 + XChaCha20Poly1305
- **X25519XChaCha20Poly1305**: Curve25519 + XChaCha20Poly1305
- **K256AeadRpo**: secp256k1 + AEAD-RPO
- **X25519AeadRpo**: Curve25519 + AEAD-RPO

## Use Cases

### ECDH

Use ECDH when you need:
- Secure key agreement between parties
- Building custom encryption protocols
- Key derivation for other purposes

### IES

Use IES when you need:
- Public-key encryption (sealed boxes)
- Encrypting to a recipient using only their public key
- No prior key exchange required

## Next Steps

- [ECDH](ecdh.md): Learn about key exchange
- [IES](ies.md): Learn about sealed boxes

