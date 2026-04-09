# zksbom-operator C++ FFI Layer

This directory contains the C++ FFI (Foreign Function Interface) code that bridges Rust and C++ for the zksbom SBOM creation and verification system.

## Architecture

The C++ FFI layer is organized into two main components:

### wrapper/
The FFI wrapper layer provides a C interface to the underlying oZKS (OpenZKS) library. This includes:
- OZKS instance management (create, destroy, get ID)
- Batch insert operations
- Query operations and proof generation
- Serialization/deserialization of commitments and proofs
- VRF key management

**Key files:**
- `cpp_wrapper.h` - C interface declarations
- `cpp_wrapper.cpp` - C wrapper implementations

### storage/
Storage backend implementations for persisting OZKS state and data.

#### sqlite/
SQLite-based storage backend providing:
- Database initialization and setup
- Table creation for merkle tree nodes and metadata
- Persistent storage of OZKS instances
- Query interface for retrieving stored nodes

**Key files:**
- `file_storage_sqlite.h` - Storage interface declarations
- `file_storage_sqlite.cpp` - SQLite storage implementations

## Build Process

The C++ code is compiled during Rust's build phase using the `cc` crate:

1. `build.rs` identifies C++ source files in this directory
2. C++ files are compiled with C++17 standard
3. The compiled object files are linked with oZKS libraries
4. `bindgen` auto-generates Rust FFI bindings from `cpp_wrapper.h`

## External Dependencies

- **oZKS library** (`third_party/oZKS/`) - Core commitment scheme implementation
- **GSL** (Microsoft Guidelines Support Library) - Via vcpkg
- **OpenSSL** - Cryptographic operations, via vcpkg
- **SQLite3** - Bundled by rusqlite Rust crate

## Include Paths

Headers resolve relative to the project root:
- `#include "../../cpp/wrapper/cpp_wrapper.h"` from code that includes wrappers
- `#include "../../cpp/storage/sqlite/file_storage_sqlite.h"` for storage

## Design Principles

1. **Clear Separation**: Wrapper vs. storage logic are separated
2. **Extensibility**: New storage backends can be added to `storage/` directory without modifying wrapper
3. **Rust Integration**: All public functions follow C FFI conventions for seamless Rust integration
4. **Memory Safety**: Careful ownership and lifetime management at the Rust-C++ boundary

## Future Enhancements

Potential new storage backends can be added:
- `storage/rocksdb/` - High-performance key-value store
- `storage/postgres/` - Distributed database backend
- `storage/memory/` - In-memory storage for testing
