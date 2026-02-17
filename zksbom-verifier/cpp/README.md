# zksbom-verifier C++ FFI Layer

This directory contains the C++ FFI (Foreign Function Interface) code that bridges Rust and C++ for proof verification.

## Overview

Unlike the main `zksbom` project which manages OZKS instances and maintains state, this verifier is stateless and focused on a single responsibility: verifying proofs.

## Architecture

### verify_wrapper
The verification FFI wrapper provides a single, focused C interface:
- `ozks_verify_proof()` - Verify a proof against a commitment

**Key files:**
- `verify_wrapper.h` - C interface declarations
- `verify_wrapper.cpp` - Verification wrapper implementation

## Design Rationale

**Stateless Design**: Unlike zksbom which manages databases and OZKS instances, zksbom-verifier:
- Takes serialized commitment and proof as input
- Performs verification in-memory
- Returns verification result
- No state is maintained between calls
- No database or persistent storage

This design makes verification:
- Simple and testable
- Suitable for lightweight deployments
- Easy to parallelize (no shared state)
- Fast and predictable

## Public Functions

### ozks_verify_proof
Verifies a proof against a commitment.

```c
int ozks_verify_proof(
    const uint8_t* commitment_bytes,
    size_t commitment_len,
    const uint8_t* proof_bytes,
    size_t proof_len
);
```

**Return values:**
- `0` - Proof is valid and element is a member
- `1` - Proof is valid and element is NOT a member
- `2` - Proof is invalid
- `-1` - Error during verification

## Build Process

The C++ code is compiled during Rust's build phase using the `cc` crate:

1. `build.rs` identifies C++ source files in this directory
2. C++ is compiled with C++17 standard
3. The compiled object files are linked with oZKS and vcpkg libraries
4. `bindgen` auto-generates Rust FFI bindings from `verify_wrapper.h`

## External Dependencies

- **oZKS library** (`third_party/oZKS/`) - Core commitment scheme and verification
- **GSL** (Microsoft Guidelines Support Library) - Via vcpkg
- **OpenSSL** - Cryptographic operations, via vcpkg

## Memory Model

**No Instance Management**: Unlike the main zksbom wrapper:
- No handle allocation or deallocation
- No state objects
- No instance IDs
- Pure function interface

All data flows through function parameters as byte arrays.

## Rust Integration

Rust code uses the generated bindings:
- Located in `src/method/ozks.rs`
- Direct FFI bindings (no intermediate safe wrappers needed)
- Verification results are interpreted and handled in Rust

## Deployment Model

`zksbom-verifier` is designed for:
- **Lightweight services**: Minimal dependencies and overhead
- **Distributed verification**: Stateless design enables easy horizontal scaling
- **API endpoints**: Each request independently verified
- **Batch verification**: Can process multiple proofs in parallel without synchronization

## Performance Characteristics

- **Latency**: Sub-millisecond verification for typical proofs
- **Throughput**: Can verify hundreds of proofs per second per core
- **Memory**: Minimal - only function parameters and temporary working memory
- **Scalability**: Trivially parallelizable across CPU cores

## Design Comparison

| Aspect | zksbom | zksbom-verifier |
|--------|--------|-----------------|
| Responsibility | Create commitments, manage state | Verify proofs only |
| State | Maintains OZKS instances and DB | Stateless |
| File count | Multiple (wrapper + storage) | Single wrapper |
| Complexity | Higher (orchestration) | Lower (focused) |
| Deployment | Long-running processes | Can be ephemeral |
| Scaling | Vertical (single instance) | Horizontal (stateless) |
