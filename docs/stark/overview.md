# STARK Proving System

Foundational components for the STARK proving system based on Plonky3.

## Overview

The STARK module exports foundational components needed to build a STARK prover/verifier and define Algebraic Intermediate Representation (AIR) for the Miden VM and other components. It primarily consists of re-exports from the Plonky3 project with some Miden-specific adaptations.

## Key Components

### Prover and Verifier

```rust
use miden_crypto::stark::{prove, verify};

// Prove a computation
let proof = prove(/* ... */).unwrap();

// Verify a proof
let is_valid = verify(/* ... */).unwrap();
```

### AIR (Algebraic Intermediate Representation)

```rust
use miden_crypto::stark::air::{Air, AirBuilder};

// Define your AIR
struct MyAir;
impl Air for MyAir {
    // ...
}
```

### Challenger

```rust
use miden_crypto::stark::challenger::{HashChallenger, SerializingChallenger64};

// Create a challenger for Fiat-Shamir
let mut challenger = HashChallenger::new(/* ... */);
```

## Related Projects

- [Plonky3](https://github.com/Plonky3/Plonky3): The underlying STARK proving system
- [p3-miden](https://github.com/0xMiden/p3-miden): Miden-specific adaptations

## Use Cases

- Building STARK provers
- Defining AIR for Miden VM
- Creating custom zero-knowledge proof systems

