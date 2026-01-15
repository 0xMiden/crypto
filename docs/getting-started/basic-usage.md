# Basic Usage

This guide provides examples of common operations with Miden Crypto.

## Hash Functions

### RPO Hash

RPO (Rescue Prime Optimized) is an algebraic hash function optimized for STARKs:

```rust
use miden_crypto::{hash::rpo::Rpo256, Felt};

// Hash field elements
let data = [Felt::new(1), Felt::new(2), Felt::new(3)];
let hash = Rpo256::hash_elements(&data);
println!("Hash: {:?}", hash);

// Hash bytes
let bytes = b"Hello, Miden!";
let hash = Rpo256::hash(bytes);
```

### RPX Hash

RPX (Rescue Prime Extended) is faster than RPO:

```rust
use miden_crypto::{hash::rpx::Rpx256, Felt};

let data = [Felt::new(1), Felt::new(2)];
let hash = Rpx256::hash_elements(&data);
```

### Poseidon2 Hash

Poseidon2 is another fast algebraic hash function:

```rust
use miden_crypto::{hash::poseidon2::Poseidon2Hasher, Felt};

let mut hasher = Poseidon2Hasher::new();
hasher.update(&[Felt::new(1), Felt::new(2)]);
let hash = hasher.finalize();
```

## Merkle Trees

### Creating a Merkle Tree

```rust
use miden_crypto::{merkle::MerkleTree, Word, Felt};

// Create leaves
let leaves = vec![
    Word::new([Felt::new(1), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
    Word::new([Felt::new(2), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
    Word::new([Felt::new(3), Felt::ZERO, Felt::ZERO, Felt::ZERO]),
];

// Build tree
let tree = MerkleTree::new(leaves).unwrap();
let root = tree.root();

// Get a Merkle path
let path = tree.get_path(0).unwrap();
```

### Sparse Merkle Tree

```rust
use miden_crypto::merkle::smt::Smt;

// Create an empty SMT
let mut smt = Smt::new();

// Insert key-value pairs
let key = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)];
let value = [Felt::new(10), Felt::new(20), Felt::new(30), Felt::new(40)];
smt.insert(key, value);

// Get root
let root = smt.root();
```

## Digital Signatures

### Ed25519 Signatures

```rust
use miden_crypto::dsa::eddsa_25519_sha512::{SecretKey, PublicKey};
use rand::rng;

let mut rng = rng();

// Generate key pair
let secret_key = SecretKey::with_rng(&mut rng);
let public_key = secret_key.public_key();

// Sign a message
let message = b"Hello, Miden!";
let signature = secret_key.sign(message);

// Verify signature
assert!(public_key.verify(message, &signature).is_ok());
```

### ECDSA Signatures

```rust
use miden_crypto::dsa::ecdsa_k256_keccak::{SecretKey, PublicKey};
use rand::rng;

let mut rng = rng();

// Generate key pair
let secret_key = SecretKey::with_rng(&mut rng);
let public_key = secret_key.public_key();

// Sign a message
let message = b"Hello, Miden!";
let signature = secret_key.sign(message);

// Verify signature
assert!(public_key.verify(message, &signature).is_ok());
```

## Encryption

### AEAD-RPO Encryption

AEAD-RPO is optimized for STARK verification:

```rust
use miden_crypto::aead::aead_rpo::AeadRpo;
use rand::rng;

let mut rng = rng();

// Generate a key
let key = AeadRpo::key_from_bytes(&[0u8; 32]).unwrap();

// Encrypt
let plaintext = b"Secret message";
let associated_data = b"metadata";
let ciphertext = AeadRpo::encrypt_bytes(&key, &mut rng, plaintext, associated_data).unwrap();

// Decrypt
let decrypted = AeadRpo::decrypt_bytes_with_associated_data(&key, &ciphertext, associated_data).unwrap();
assert_eq!(decrypted, plaintext);
```

### XChaCha20Poly1305 Encryption

For general-purpose encryption:

```rust
use miden_crypto::aead::xchacha::XChaCha20Poly1305;
use rand::rng;

let mut rng = rng();

// Generate a key
let key = XChaCha20Poly1305::key_from_bytes(&[0u8; 32]).unwrap();

// Encrypt
let plaintext = b"Secret message";
let associated_data = b"metadata";
let ciphertext = XChaCha20Poly1305::encrypt_bytes(&key, &mut rng, plaintext, associated_data).unwrap();

// Decrypt
let decrypted = XChaCha20Poly1305::decrypt_bytes_with_associated_data(&key, &ciphertext, associated_data).unwrap();
assert_eq!(decrypted, plaintext);
```

## Integrated Encryption Scheme (IES)

Sealed boxes allow encrypting to a recipient using only their public key:

```rust
use miden_crypto::{
    dsa::eddsa_25519_sha512::SecretKey,
    ies::{SealingKey, UnsealingKey},
};
use rand::rng;

let mut rng = rng();

// Generate key pair
let secret_key = SecretKey::with_rng(&mut rng);
let public_key = secret_key.public_key();

// Create sealing and unsealing keys
let sealing_key = SealingKey::X25519XChaCha20Poly1305(public_key);
let unsealing_key = UnsealingKey::X25519XChaCha20Poly1305(secret_key);

// Seal (encrypt) a message
let message = b"Hello, Miden!";
let sealed = sealing_key.seal_bytes(&mut rng, message).unwrap();

// Unseal (decrypt) the message
let opened = unsealing_key.unseal_bytes(sealed).unwrap();
assert_eq!(opened.as_slice(), message);
```

## Random Number Generation

### RPO Random Coin

```rust
use miden_crypto::rand::RpoRandomCoin;
use miden_crypto::Felt;

let mut coin = RpoRandomCoin::new(&[Felt::new(1), Felt::new(2)]);

// Draw random field elements
let element1 = coin.draw_element();
let element2 = coin.draw_element();
```

## Field Elements and Words

### Working with Field Elements

```rust
use miden_crypto::Felt;

// Create field elements
let zero = Felt::ZERO;
let one = Felt::ONE;
let value = Felt::new(42);

// Operations
let sum = one + one;
let product = value * Felt::new(2);
```

### Working with Words

```rust
use miden_crypto::{Word, Felt};

// Create a word (4 field elements)
let word = Word::new([
    Felt::new(1),
    Felt::new(2),
    Felt::new(3),
    Felt::new(4),
]);

// Access elements
let first = word[0];
```

## Next Steps

Explore the detailed documentation for each module:

- [Hash Functions](../hash/overview.md)
- [Merkle Trees](../merkle/overview.md)
- [Digital Signatures](../dsa/overview.md)
- [Encryption](../encryption/overview.md)
- [Key Exchange](../key-exchange/overview.md)

